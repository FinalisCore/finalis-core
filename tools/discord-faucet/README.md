# Testnet bond faucet (Discord bot)

`/faucet address:tsc1…` in the faucet channel queues one free validator bond per Discord account and
per address, for the **first 128 grants only** (`MAX_GRANTS`; a failed payment frees its slot). After
that the bot answers that validators buy or receive their coins. It pays the current minimum bond
(`finalis-cli economics_status`, 150 FLS at launch) plus 1 FLS for fees, one payment at a time and in
request order, and pings the user when the payment is sent and again when it is final. These are the
launch model's faucet rules (`mainnet/MAINNET_PLAN.md`).

Coins only exist as block rewards (there is no premine), so the faucet can only pay out what the
validator has earned. Requests wait in the queue until the faucet holds enough; the bot tells each
user their place and an estimated time.

- `faucet_core.py`: queue, limits and payments (no Discord code). `python3 -m unittest test_faucet_core`
  runs its offline tests.
- `faucet_bot.py`: the Discord front end.
- The bot signs with its **own key**, never the validator's. `finalis-faucet-sweep.timer` moves the
  validator's rewards to the faucet address every hour.

## Setup on the node host

1. **Discord application.** At <https://discord.com/developers/applications>: New Application → Bot →
   Reset Token (copy it). Under OAuth2 → URL Generator pick the scopes `bot` and `applications.commands`
   and the permission *Send Messages*, open the generated URL and add the bot to your server. Enable
   Developer Mode in Discord (Settings → Advanced) to copy the server id, the faucet channel id and
   your own user id (right-click → Copy ID).

2. **Faucet key** (testnet only; the bot runs unattended, so it is stored without a passphrase):

   ```bash
   mkdir -p ~/finalis-faucet && chmod 700 ~/finalis-faucet
   ~/finalis-core/build/finalis-cli --testnet wallet_create --out ~/finalis-faucet/faucet.json
   ```

   Note the printed `address=tsc1…`.

3. **Python environment:**

   ```bash
   sudo apt install -y python3-venv
   python3 -m venv ~/finalis-faucet/venv
   ~/finalis-faucet/venv/bin/pip install -r ~/finalis-core/tools/discord-faucet/requirements.txt
   ```

4. **Configuration:** copy `faucet.env.example` to `/etc/finalis-faucet.env`, fill in the token, ids
   and faucet address, then `sudo chmod 600 /etc/finalis-faucet.env`.

5. **Services:**

   ```bash
   cd ~/finalis-core/tools/discord-faucet
   sudo cp finalis-faucet.service finalis-faucet-sweep.service finalis-faucet-sweep.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now finalis-faucet-sweep.timer finalis-faucet
   ```

## Day to day

```bash
sudo journalctl -u finalis-faucet -f                         # bot log
sudo journalctl -u finalis-faucet-sweep -n 20                # last sweeps
sqlite3 ~/finalis-faucet/faucet.sqlite 'SELECT id, user_id, address, state, txid FROM grants'
```

A payment that fails is marked `failed` and never retried automatically, so an unclear broadcast can
not pay twice; the bot pings `FAUCET_ADMIN_USER_ID`. After checking the txid, retry it with
`UPDATE grants SET state = 'queued' WHERE id = <id>`.
