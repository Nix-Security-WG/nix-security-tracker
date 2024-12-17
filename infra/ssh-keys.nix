rec {
  eelco = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnI5L6oCgFyvEesL04LnbnH1TBhegq1Yery6TNlIRAA edolstra@gmail.com";

  zimbatm = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOuiDoBOxgyer8vGcfAIbE6TC4n4jo8lhG9l01iJ0bZz zimbatm";

  vcunat = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4IJkFIVyImkfD4fM89ya+hy2ig8kUg09PCdjB5rS82akFoucYZSYMG41ZrlMT5LAikIgWusBzpO5bBkqxqcYqaYK/VF06zVBk3kF1pAIoitst9z0PLXY8/N+bFJg6oT7p6EWGRvFggUviSTTvJFMNUdDgEpsLqLp8+IYXjfM3Cz6+TQmyWQSockobRqgdILTjc1p2uxmNSzy2fElpZ0sKRPLNYG4SVPBPnOavs1KPOtyC1pIHOuz5A605gPLFXoWpX2lIK6atmGheiHxURDAX3pANVm+iMmnjteP0jEGU26/SPqgVP3OxdcryHxL3WnSJGtTnycoa30qP/Edmy9vB";

  hexa-gaia = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAWQRR7dspgQ6kCwyFnoVlgmmPR4iWL1+nvq6a5ad2Ug hexa@gaia";
  hexa-helix = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFSpdtIxIBFtd7TLrmIPmIu5uemAFJx4sNslRsJXfFxr hexa@helix";

  edef = "cert-authority ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCvb/7ojfcbKvHIyjnrNUOOgzy44tCkgXY9HLuyFta1jQOE9pFIK19B4dR9bOglPKf145CCL0mSFJNNqmNwwavU2uRn+TQrW+U1dQAk8Gt+gh3O49YE854hwwyMU+xD6bIuUdfxPr+r5al/Ov5Km28ZMlHOs3FoAP0hInK+eAibioxL5rVJOtgicrOVCkGoXEgnuG+LRbOYTwzdClhRUxiPjK8alCbcJQ53AeZHO4G6w9wTr+W5ILCfvW4OmUXCX01sKzaBiQuuFCF6M/H4LlnsPWLMra2twXxkOIhZblwC+lncps9lQaUgiD4koZeOCORvHW00G0L39ilFbbnVcL6Itp/m8RRWm/xRxS4RMnsdV/AhvpRLrhL3lfQ7E2oCeSM36v1S9rdg6a47zcnpL+ahG76Gz39Y7KmVRQciNx7ezbwxj3Q5lZtFykgdfGIAN+bT8ijXMO6m68g60i9Bz4IoMZGkiJGqMYLTxMQ+oRgR3Ro5lbj7E11YBHyeimoBYXYGHMkiuxopQZ7lIj3plxIzhmUlXJBA4jMw9KGHdYaLhaicIYhvQmCTAjrkt2HvxEe6lU8iws2Qv+pB6tAGundN36RVVWAckeQPZ4ZsgDP8V2FfibZ1nsrQ+zBKqaslYMAHs01Cf0Hm0PnCqagf230xaobu0iooNuXx44QKoDnB+w== edef";

  mic92-turingmachine = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEVSsc5mlP8aWiUVwWWM3gKlB5LHVpmKSifnDyox/BnVAAAABHNzaDo= yubikey1";
  mic92-evo = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCsjXKHCkpQT4LhWIdT0vDM/E/3tw/4KHTQcdJhyqPSH0FnwC8mfP2N9oHYFa2isw538kArd5ZMo5DD1ujL5dLk= ssh@secretive.Joerg’s-Laptop.local";

  jfly = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImw0Xc1buEQ9WOskyGGeg3QwdbU7DTUQBiu02fObDlm jfly";

  infra-core = [
    edef
    hexa-gaia
    hexa-helix
    vcunat
    zimbatm
    mic92-turingmachine
    mic92-evo
  ];

  infra = infra-core ++ [ jfly ];
}
