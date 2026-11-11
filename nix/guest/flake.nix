{
  description = "sandy guest microVMs for live acceptance (#26/#27)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    microvm.url = "github:microvm-nix/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      microvm,
    }:
    let
      # `mkGuest`/`mkTopology` (plus the `commonModule` protocol wiring and the
      # agent overlay they bake in) are the shared guest-composition module
      # (#324): this nested flake's own `../../flake.nix` exposes the same
      # functions as `lib.mkGuest`/`lib.mkTopology` for a consuming flake, both
      # built from this one file so they can't drift apart. Imported directly
      # by relative path (not as a flake input): a `path:../..` input here
      # would pull the root flake's own nixpkgs/microvm pins into this nested
      # flake's lock, when each flake's pins are meant to stay independent.
      guestLib = import ../lib/guest.nix { inherit nixpkgs microvm; };
      inherit (guestLib) mkGuest mkTopology;

      # Guest networking for the #29 live egress gate and the #602 `nic` profile (the vfkit guest carries it
      # too; there the NIC has no host egress boundary, #603). sandy's qemu backend adds
      # the NIC itself (`-netdev tap,ifname=$SANDY_TAP` + virtio-net with the fixed
      # `02:00:00:00:00:01` MAC) because it assembles its own qemu argv rather than
      # using microvm's declaredRunner — so the guest only needs to bring up and
      # DHCP whatever ethernet interface appears. `Type = "ether"` matches it
      # without depending on a predictable name; the host side of the tap runs the
      # DHCP server (the gate starts dnsmasq). The guest's own firewall is off: the
      # host enforces egress (guest-scoped nftables on the tap), and the
      # "bypass impossible" row flushes the guest's rules anyway.
      networkingModule =
        { pkgs, ... }:
        {
          networking.useNetworkd = true;
          systemd.network.enable = true;
          systemd.network.networks."10-ether" = {
            matchConfig.Type = "ether";
            networkConfig.DHCP = "yes";
          };
          networking.firewall.enable = false;
          # `nft` in the guest so the #29 "bypass impossible" row can really flush
          # the guest's own ruleset — otherwise that step is a silent no-op and the
          # assertion is vacuous. `glibc.bin` for `getent`: NixOS doesn't put it on
          # PATH by default, and the #376 live gate needs it to prove the guest
          # really can't resolve a name through a host-local resolver.
          environment.systemPackages = [
            pkgs.nftables
            pkgs.glibc.bin
          ];
        };

      # A minimal HTTP service for the environment and bridge live gates. The service workload kind (#589) starts
      # it, never the image; the image holds no key, token or config. `sandy-http-ready` is the probe: it succeeds
      # once an HTTP server answers on the loopback port with a status below 500 (a service may reply 503 while it
      # starts, and 401 once auth is on), so readiness never rests on console text. It proves an HTTP listener, not
      # that the service's own API is up.
      readyProbe =
        pkgs:
        pkgs.writeShellScriptBin "sandy-http-ready" ''
          port=''${1:-3773}
          case "$port" in
            "" | *[!0-9]* | ??????*)
              echo "sandy-http-ready: the port must be 1 to 5 digits, got: $port" >&2
              exit 2
              ;;
          esac
          if [ "$port" -gt 65535 ]; then
            echo "sandy-http-ready: the port must be at most 65535, got: $port" >&2
            exit 2
          fi
          code=$(${pkgs.curl}/bin/curl --silent --noproxy '*' --max-time 2 --output /dev/null \
            --write-out '%{http_code}' "http://127.0.0.1:$port/") || exit 1
          [ "$code" -ge 100 ] && [ "$code" -lt 500 ]
        '';

      # `sandy-example-service --port <p> [--dir <d>]`: busybox httpd on loopback, serving <d>. Any path is 404 and
      # counts as Ready for the probe above.
      exampleService =
        pkgs:
        pkgs.writeShellScriptBin "sandy-example-service" ''
          port=3773
          dir=/var/lib/service
          while [ $# -gt 0 ]; do
            case "$1" in
              --port) port=$2; shift 2 ;;
              --dir) dir=$2; shift 2 ;;
              *) shift ;;
            esac
          done
          mkdir -p "$dir"
          exec ${pkgs.busybox}/bin/busybox httpd -f -p "127.0.0.1:$port" -h "$dir"
        '';

      serviceModule =
        { pkgs, ... }:
        {
          # The service account (#589): the agent runs as root and starts a service manifest's `service.user` through
          # `runuser -u <user> --`. A system user with its own home, and no login shell.
          users.groups.service = { };
          users.users.service = {
            isSystemUser = true;
            group = "service";
            home = "/var/lib/service";
            createHome = true;
            shell = "${pkgs.shadow}/bin/nologin";
          };
          environment.systemPackages = [
            (exampleService pkgs)
            (readyProbe pkgs)
            pkgs.curl
            pkgs.util-linux # runuser
          ];
        };

      # GitHub credential consumption for a `sandy run --credential` job. The scoped
      # token is staged read-only at /run/sandy/secrets/GITHUB_TOKEN (sandy fixes
      # that name). Both consumers read the FILE at use-time, not the boot-time
      # `$GITHUB_TOKEN` env snapshot, so a mid-run refresh (#49) is picked up: the
      # env export happens once at login and can never update a running process.
      #   - git over HTTPS: a named credential helper on PATH returns the current
      #     token per operation as `x-access-token:<token>`, scoped to github.com so
      #     the token never travels to another remote.
      #   - the gh CLI: a PATH wrapper re-reads the file into GH_TOKEN and execs the
      #     real gh, so `gh api`/`gh pr` see the current token per call.
      # Both are shell-independent on purpose: a helper binary and a wrapper binary
      # are found by non-interactive shells, scripts, and anything that execs the
      # tool, which a shell alias is not.
      credentialModule =
        { pkgs, ... }:
        let
          tokenFile = "/run/sandy/secrets/GITHUB_TOKEN";
          # git invokes `git credential-sandy-gh <op>`; only `get` returns anything.
          gitHelper = pkgs.writeShellScriptBin "git-credential-sandy-gh" ''
            [ "$1" = get ] || exit 0
            [ -r ${tokenFile} ] || exit 0
            printf 'username=x-access-token\npassword=%s\n' "$(cat ${tokenFile})"
          '';
          # The only `gh` on PATH: refresh-safe GH_TOKEN, re-read each invocation,
          # then exec the real gh by store path.
          ghWrapper = pkgs.writeShellScriptBin "gh" ''
            if [ -r ${tokenFile} ]; then
              GH_TOKEN="$(cat ${tokenFile})"
              export GH_TOKEN
            fi
            exec ${pkgs.gh}/bin/gh "$@"
          '';
        in
        {
          programs.git = {
            enable = true;
            config.credential."https://github.com".helper = "sandy-gh";
          };
          environment.systemPackages = [
            gitHelper
            ghWrapper
          ];
        };

      # qemu guest for the Linux node (x86_64-linux/KVM), console ttyS0. Carries the
      # networking module so the #29 egress gate has guest egress to filter.
      qemuGuest = mkGuest {
        system = "x86_64-linux";
        hypervisor = "qemu";
        extraModules = [
          networkingModule
          credentialModule
        ];
      };

      # The same guests with the example service.
      qemuServiceGuest = mkGuest {
        system = "x86_64-linux";
        hypervisor = "qemu";
        extraModules = [
          networkingModule
          credentialModule
          serviceModule
        ];
      };

      vfkitServiceGuest = mkGuest {
        system = "aarch64-linux";
        hypervisor = "vfkit";
        vmHostPackages = nixpkgs.legacyPackages.aarch64-darwin;
        extraModules = [
          networkingModule
          credentialModule
          serviceModule
        ];
      };

      # vfkit guest for an Apple-silicon host (aarch64-darwin host, aarch64-linux guest — vfkit
      # requires matching arch), console hvc0. The kernel/initrd/erofs build on
      # the aarch64-linux linux-builder; the runner assembles on darwin.
      vfkitGuest = mkGuest {
        system = "aarch64-linux";
        hypervisor = "vfkit";
        vmHostPackages = nixpkgs.legacyPackages.aarch64-darwin;
        extraModules = [
          networkingModule
          credentialModule
        ];
      };

    in
    {
      # microvm.nix's own runners — used to prove each guest boots and speaks the
      # protocol before sandy's backend drives it.
      packages.x86_64-linux.guest-runner = qemuGuest.config.microvm.declaredRunner;
      packages.aarch64-darwin.guest-runner-vfkit = vfkitGuest.config.microvm.declaredRunner;
      # The service guest's runners. `sandy run` evaluates a topology but does not build its artifacts, so a
      # caller builds these first, as the live tests do for the base guest.
      packages.x86_64-linux.guest-runner-service = qemuServiceGuest.config.microvm.declaredRunner;
      packages.aarch64-darwin.guest-runner-vfkit-service =
        vfkitServiceGuest.config.microvm.declaredRunner;

      # The built guest configs (the topology attrs read kernel/initrd/store off
      # these).
      nixosConfigurations.sandy-guest-qemu = qemuGuest;
      nixosConfigurations.sandy-guest-vfkit = vfkitGuest;
      nixosConfigurations.sandy-guest-qemu-service = qemuServiceGuest;
      nixosConfigurations.sandy-guest-vfkit-service = vfkitServiceGuest;

      # The guest-side sandy-agent, per guest system (#238) — the same
      # `pkgs.sandy-agent` the guest config itself carries (via the overlay
      # applied in `mkGuest`), re-exposed here for direct `nix build`.
      packages.x86_64-linux.sandy-agent = qemuGuest.pkgs.sandy-agent;
      packages.aarch64-linux.sandy-agent = vfkitGuest.pkgs.sandy-agent;

      # Eval-only acceptance for the service guest image: it carries the example service and the readiness probe.
      checks.x86_64-linux.service-guest-packages =
        let
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
          config = self.nixosConfigurations.sandy-guest-qemu-service.config;
          names = map (p: p.name) config.environment.systemPackages;
          wanted = [
            "sandy-example-service"
            "sandy-http-ready"
          ];
          missing = builtins.filter (w: !(builtins.elem w names)) wanted;
        in
        assert missing == [ ] || throw "the service guest image lacks: ${builtins.toString missing}";
        # The agent runs as root and starts a service manifest's `service.user` through `runuser -u <user>` (#589),
        # so the guest must define that account: a non-root user with a home directory that it owns.
        assert
          (
            config.users.users ? service
            && config.users.users.service.isSystemUser
            && config.users.users.service.group == "service"
            && config.users.users.service.home == "/var/lib/service"
            && config.users.users.service.createHome
            && pkgs.lib.hasSuffix "/nologin" (toString config.users.users.service.shell)
          )
          || throw "the service guest defines no service system user with a home directory, its own group and no login shell";
        pkgs.runCommand "service-guest-packages" { } "touch $out";

      # The readiness probe's behaviour against a throwaway local HTTP server: any status below 500 means the
      # server answers (a service may answer 503 while it starts, and 401 once auth is on), 5xx and a closed port do not, and a
      # port argument that is not digits is refused.
      checks.x86_64-linux.http-ready-probe =
        let
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
        in
        pkgs.runCommand "http-ready-probe"
          {
            nativeBuildInputs = [
              pkgs.python3
              (readyProbe pkgs)
            ];
          }
          ''
            cat > server.py <<'PY'
            import http.server, sys
            code, port = int(sys.argv[1]), int(sys.argv[2])
            class H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(code)
                    self.end_headers()
                def log_message(self, *args):
                    pass
            http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
            PY
            refuses() { # refuses <label> <probe args...>: a bad argument is a usage error (2), not a failed probe (1)
              label=$1; shift
              rc=0; sandy-http-ready "$@" 2>/dev/null || rc=$?
              [ "$rc" = 2 ] || { echo "$label: wanted exit 2, got $rc" >&2; exit 1; }
            }
            expect() { # expect <want: ok|fail> <label> <probe args...>
              want=$1; label=$2; shift 2
              if sandy-http-ready "$@" 2>/dev/null; then got=ok; else got=fail; fi
              [ "$got" = "$want" ] || { echo "$label: wanted $want, got $got" >&2; exit 1; }
            }
            n=0
            for case in 200:ok 302:ok 401:ok 503:fail 500:fail; do
              code=''${case%%:*}; want=''${case##*:}; port=$((18700 + n)); n=$((n + 1))
              python3 server.py "$code" "$port" & pid=$!
              for _ in $(seq 50); do (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null && break; sleep 0.1; done
              expect "$want" "status $code" "$port"
              kill "$pid"; wait "$pid" 2>/dev/null || true
            done
            expect fail "nothing listening" 18799
            refuses "port with userinfo" "18700@otherhost"
            refuses "port with a command" "18700; true"
            refuses "port above 65535" 65536
            refuses "huge port" 99999999999999999999
            touch $out
          '';

      # sandy's `Topology` per guest: `nix eval --json <flake>#topologies.<sys>.<hv>`.
      topologies = {
        x86_64-linux.qemu = mkTopology qemuGuest;
        aarch64-linux.vfkit = mkTopology vfkitGuest;
        x86_64-linux.qemu-service = mkTopology qemuServiceGuest;
        aarch64-linux.vfkit-service = mkTopology vfkitServiceGuest;
      };
    };
}
