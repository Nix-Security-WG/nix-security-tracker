# Nixpkgs Security Tracker

The **Nixpkgs Security Tracker** is a web service for managing information on vulnerabilities in software distributed through Nixpkgs.

This tool is eventually supposed to be used by the Nixpkgs community to effectively work through security advisories.
We identified three interest groups that the tool is going to address:

**Nix security team members** use this to access an exhaustive feed of CVEs being published, in order to decide on their relevance, link them to affected packages in Nixpkgs, notify package maintainers and discuss the issue with other team members.

**Nixpkgs package maintainers** are able to get notified and receive updates on security issues that affect packages that they maintain.
By discussing issues with security team members and other maintainers, they can further help on figuring out which channels and packages are affected and ultimately work on fixes for the issue.

**Nixpkgs users** are able to subscribe and stay updated on ongoing security issues that affect the packages they use.
