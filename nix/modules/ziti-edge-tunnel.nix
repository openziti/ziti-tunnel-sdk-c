self:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.programs.ziti-edge-tunnel;

  enrollmentServices = lib.mapAttrs' (
    name: icfg:
    lib.nameValuePair "ziti-edge-tunnel-enroll-${name}" {
      description = "Enroll Ziti Edge Tunnel identity '${name}'";
      after = [
        "network-online.target"
        "local-fs.target"
        "ziti-edge-tunnel-identities-perms.service"
      ];
      requires = [ "network-online.target" ];
      before = [ "ziti-edge-tunnel.service" ];
      serviceConfig = {
        Type = "oneshot";
        UMask = "0007";
        ConditionPathExists = "!${cfg.identityDir}/${icfg.identityFileName}";
        ExecStart = lib.concatStringsSep " " (
          [
            "${lib.getExe ziti-edge-tunnel}"
            "enroll"
            "--jwt ${lib.escapeShellArg icfg.jwtFile}"
            "--identity ${lib.escapeShellArg "${cfg.identityDir}/${icfg.identityFileName}"}"
          ]
          ++ map lib.escapeShellArg icfg.extraArgs
        );
      };
    }
  ) cfg.enrollment.identities;

  enrollmentServiceNames = map (n: "${n}.service") (lib.attrNames enrollmentServices);

  ziti-edge-tunnel = self.packages.${pkgs.system}.ziti-edge-tunnel;
in
{
  options.programs.ziti-edge-tunnel = {
    enable = lib.mkEnableOption "Ziti Edge Tunnel";

    identityDir = lib.mkOption {
      type = lib.types.str;
      default = "/opt/openziti/etc/identities";
      description = "Directory containing Ziti identities used by the tunnel";
    };

    dnsIpRange = lib.mkOption {
      type = lib.types.str;
      default = "100.64.0.1/10";
      description = "CIDR range for Ziti DNS intercept";
    };

    verbose = lib.mkOption {
      type = lib.types.str;
      default = "info";
      description = "Log verbosity level (e.g. info, debug, trace)";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional environment file for overriding service defaults";
    };

    extraUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Users to add to the ziti group, granting access to the Ziti socket.";
    };

    enrollment = {
      identities = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule (
            { name, ... }:
            {
              options = {
                jwtFile = lib.mkOption {
                  type = lib.types.str;
                  description = ''
                    Path to the enrollment JWT. This can point to a sops-nix secret like
                    `config.sops.secrets."ziti-''${name}-jwt".path`.
                  '';
                };

                identityFileName = lib.mkOption {
                  type = lib.types.str;
                  default = "${name}.json";
                  defaultText = lib.literalExpression ''"$${config.program.ziti-edge-tunnel.enrollment.identities.*.name}.json"'';
                  description = "Name of the identity file. File lives in `program.ziti-edge-tunnel.identityDir`";
                };

                extraArgs = lib.mkOption {
                  type = lib.types.listOf lib.types.str;
                  default = [ ];
                  description = "Extra flags to pass to `ziti-edge-tunnel enroll`.";
                };
              };
            }
          )
        );
        default = { };
        description = "Set of identities to enroll at boot (each gets its own oneshot service).";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ ziti-edge-tunnel ];

    users.users = lib.mkMerge (map (u: { ${u}.extraGroups = [ "ziti" ]; }) cfg.extraUsers);
    users.groups.ziti = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.identityDir} 0770 root root -"
    ];

    systemd.services = {
      # Ensure recursive ownership and permissions match policy
      ziti-edge-tunnel-identities-perms = {
        description = "Normalize Ziti identities directory ownership and permissions";
        wantedBy = [ "multi-user.target" ];
        before = [ "ziti-edge-tunnel.service" ] ++ enrollmentServiceNames;
        after = [ "local-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = [
            "${pkgs.coreutils}/bin/chgrp -cR root ${cfg.identityDir}"
            "${pkgs.coreutils}/bin/chmod -cR ug=rwX,o-rwx ${cfg.identityDir}"
          ];
        };
      };

      ziti-edge-tunnel = lib.mkIf cfg.enable {
        description = "Ziti Edge Tunnel";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ] ++ enrollmentServiceNames;
        requires = enrollmentServiceNames;
        wants = [ "network-online.target" ];

        # Provide tools the tunnel shells out to (e.g., awk for route parsing)
        path = [
          pkgs.iproute2
          pkgs.gawk
        ];

        serviceConfig = {
          Type = "simple";
          UMask = "0007";
          AmbientCapabilities = [ "CAP_NET_ADMIN" ];
          ExecStart = "${lib.getExe ziti-edge-tunnel} run --verbose=${cfg.verbose} --dns-ip-range=${cfg.dnsIpRange} --identity-dir=${cfg.identityDir}";
          Restart = "always";
          RestartSec = 3;
        }
        // lib.optionalAttrs (cfg.environmentFile != null) {
          EnvironmentFile = cfg.environmentFile;
        };
      };
    }
    // enrollmentServices;
  };
}
