# Configuration

Configuration files for the application are stored in `$HOME/.config/ssltest`. They can be edited to change the rules by which the application is rating the web server parameters. In the sections bellow you can see examples of what can be configured.

- You need to run the application at least once in order to copy the files to the config folder.

You can also use the `-c/--config` parameter to specify a custom folder for the config files. Files in the custom folder have higher priority then the default directory.

## Scanning speed

The configuration file `network_profiles.json` can be edited to slow down or speed up. For example slowing down the scanning speed can be usefull if the scripts scanning process is flagged as a false positive detection of a DoS attack.

Network profiles can then be assigned to a function that uses specified profile. Usages for these can be found in the `nework_profile_usage.json` configuration file.

## Scanning security policy

If a protocol or an algorithm becomes insecure, it is possible to edit the `security_levels.json` file to change how the script rates certain security parameters. For example if AES ever becomes insecure, you can move it from the level `1` into level `2` in the `sym_enc_algorithm_key_length` section of the configuration file.

## Other configuration files

Other configuration files are having a worth a look over if you are interested in more customization of the script.
