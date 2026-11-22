# to-recolte

Harvest job for arXiv e-prints listed by identifier. The job downloads each e-print at a low rate (one request every 3 seconds),
opens none of them, and uploads one symmetric-encrypted package plus a plain count file (identifier, HTTP status, size, sha1).
No source file is stored or published in clear here. Research use only; nothing is redistributed.
