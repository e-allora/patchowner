# Security

PatchOwner is a local proof of concept. It reads a CSV you give it, downloads the public CISA KEV catalog,
and writes one HTML file. It does not send email, open tickets, contact anyone, or phone home. The web demo
(`patchowner serve`) binds to `127.0.0.1` by default and keeps what people did about a notice in a JSON file
on the machine running it. The static copy at https://patchowner.com has no server behind it: button clicks
stay in your browser.

## What this tool is not

It is not security advice. Every vulnerability it shows is on the CISA KEV catalog, which means it is being
exploited in the wild, and CISA's guidance is to patch immediately. The urgency labels come from an editable
policy table and are for testing the prioritization logic. See the About tab of any report.

## Reporting a problem

If you find a security problem in PatchOwner itself (for example, a way for an uploaded CSV to run script in
the report, or a path the server should not write to), please
[open an issue](https://github.com/e-allora/patchowner/issues). If the details are sensitive, say so in the
issue without the specifics and we will arrange a private channel.

Please do not report vulnerabilities in the products that appear in a report here. Those belong to the
vendor named on the notice and to CISA.
