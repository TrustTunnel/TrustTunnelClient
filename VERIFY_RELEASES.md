# Verifying TrustTunnelClient Releases

Since TrustTunnelClient v0.99.104 we sign the executable files we build so that you can verify they are really created by us and no one else. Inside an archive file there's a small file with .sig extension which contains the signature data. In a hypothetic situation when the binary file inside an archive is replaced by someone, you'll know that it isn't an official release from AdGuard.

## How to verify that the executable file was built by AdGuard?

1. Unpack the TrustTunnelClient archive file.
2. Import TrustTunnelClient public key from keyserver. For current release, run:

    ```text
    gpg --keyserver 'keys.openpgp.org' --recv-key '28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6'
    ```

    The above command will print something similar to:

    ```text
    gpg: key 0FE641E7235E2EC6: public key "AdGuard <devteam@adguard.com>" imported
    gpg: Total number processed: 1
    gpg:               imported: 1
    ```

3. Verify. On Unix:

   ```text
   gpg --verify trusttunnel_client/trusttunnel_client_setup_wizard.sig
   gpg --verify trusttunnel_client/trusttunnel_client.sig
   ```

   On Windows (you might need to install PGP):

   ```text
   gpg --verify trusttunnel_client/trusttunnel_client_setup_wizard.exe.sig
   gpg --verify trusttunnel_client/trusttunnel_client.exe.sig
   ```

   You'll see something like this:

   ```text
   gpg: assuming signed data in 'trusttunnel_client'
   gpg: Signature made Mon 2 Feb 2026 19:30:55 MSK
   gpg:                using RSA key 28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6
   gpg:                issuer "devteam@adguard.com"
   gpg: Good signature from "AdGuard <devteam@adguard.com>" [ultimate]
   ```

   Check the following:

   - RSA key: must be 28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6;
   - Issuer name: must be AdGuard;
   - E-mail address: must be devteam@adguard.com.

   There may also be the following warning:

   ```text
   gpg: WARNING: The key's User ID is not certified with a trusted signature!
   gpg:          There is no indication that the signature belongs to the owner.
   Primary key fingerprint: 2864 5AC9 776E C4C0 0BCE  2AFC 0FE6 41E7 235E 2EC6
   ```
