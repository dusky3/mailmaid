## Changelog

### 1.1.0

* Added a child_spec for Mailmaid.SMTP.Server
* Mailmaid.SMTP.Server is now a GenServer, making it friendlier in supervision trees, this will also allow restoring the multi-listener feature from gen_smtp

### 1.0.0

* New SMTP.Client, to get the old behaviour use SMTP.LegacyClient instead
