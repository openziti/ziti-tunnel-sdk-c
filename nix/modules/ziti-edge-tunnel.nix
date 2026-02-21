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
      wants = [ "network-online.target" ];
      before = [ "ziti-edge-tunnel.service" ];
      serviceConfig = {
        Type = "oneshot";
        User = cfg.service.user;
        UMask = "0007";
        ConditionPathExists = "!${icfg.identityFile}";
        ExecStart = lib.concatStringsSep " " (
          [
            "${pkgs.ziti-edge-tunnel}/bin/ziti-edge-tunnel"
            "enroll"
            "--jwt ${lib.escapeShellArg icfg.jwtFile}"
            "--identity ${lib.escapeShellArg icfg.identityFile}"
          ]
          ++ map lib.escapeShellArg icfg.extraArgs
        );
      };
    }
  ) cfg.enrollment.identities;

  enrollmentServiceNames = map (n: "${n}.service") (lib.attrNames enrollmentServices);
in
{
  options.programs.ziti-edge-tunnel = {
    enable = lib.mkEnableOption "Ziti Edge Tunnel";

    identityDir = lib.mkOption {
      type = lib.types.str;
      default = "/opt/openziti/etc/identities";
      description = "Directory containing Ziti identities used by the tunnel";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "ziti";
      description = "User to run the tunnel service as";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "ziti";
      description = "Group owning identities; contents are writable by this group";
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

                identityFile = lib.mkOption {
                  type = lib.types.str;
                  default = "${cfg.service.identityDir}/${name}.json";
                  description = "Absolute path of the enrolled identity JSON to create if missing.";
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
    environment.systemPackages = [ pkgs.ziti-edge-tunnel ];

    # Declare the user and group to ensure they exist
    users.users.${cfg.service.user} = {
      isSystemUser = true;
      group = cfg.service.group;
    };
    users.groups.${cfg.service.group} = { };

    # Ensure identity directory exists with secure defaults and proper group
    systemd.tmpfiles.rules = [
      "d ${cfg.service.identityDir} 0770 ${cfg.service.user} ${cfg.service.group} -"
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
            "${pkgs.coreutils}/bin/chgrp -cR ${cfg.service.group} ${cfg.service.identityDir}"
            "${pkgs.coreutils}/bin/chmod -cR ug=rwX,o-rwx ${cfg.service.identityDir}"
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
          User = cfg.service.user;
          UMask = "0007";
          AmbientCapabilities = [ "CAP_NET_ADMIN" ];
          ExecStart = "${pkgs.ziti-edge-tunnel}/bin/ziti-edge-tunnel run --verbose=${cfg.service.verbose} --dns-ip-range=${cfg.service.dnsIpRange} --identity-dir=${cfg.service.identityDir}";
          Restart = "always";
          RestartSec = 3;
        }
        // lib.optionalAttrs (cfg.service.environmentFile != null) {
          EnvironmentFile = cfg.service.environmentFile;
        };
      };
    }
    // enrollmentServices;
  };
}
