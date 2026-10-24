#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Discord front end of the testnet bond faucet (logic in faucet_core.py). See README.md.

Slash command: /faucet address:<tsc1...>. Works only in the configured channel. Every minute the bot
finishes or starts one payment and pings the user in that channel.
"""

from __future__ import annotations

import asyncio
import logging
import os

import discord
from discord import app_commands

from faucet_core import Cli, Faucet, Rpc, Store


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise SystemExit(f"missing environment variable {name}")
    return value


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    rpc_url = env("FAUCET_RPC", "http://127.0.0.1:19544/rpc")
    guild_id = int(env("FAUCET_GUILD_ID"))
    channel_id = int(env("FAUCET_CHANNEL_ID"))
    admin_user_id = env("FAUCET_ADMIN_USER_ID", "")
    faucet = Faucet(
        store=Store(env("FAUCET_DB", "/var/lib/finalis-faucet/faucet.sqlite")),
        rpc=Rpc(rpc_url),
        cli=Cli(env("FAUCET_CLI"), env("FAUCET_NODE_DB"), env("FAUCET_KEY_FILE"), env("FAUCET_KEY_PASS", ""), rpc_url),
        faucet_address=env("FAUCET_ADDRESS"),
        fee_buffer_units=int(env("FAUCET_FEE_BUFFER_UNITS", "100000000")),  # 1 FLS
        income_units_per_block=int(env("FAUCET_INCOME_UNITS_PER_BLOCK", "575000000")),  # ~5.75 FLS
    )
    lock = asyncio.Lock()  # faucet calls run one at a time, in a worker thread

    client = discord.Client(intents=discord.Intents.default())
    tree = app_commands.CommandTree(client)
    guild = discord.Object(id=guild_id)

    async def run(fn, *args):
        async with lock:
            return await asyncio.to_thread(fn, *args)

    @tree.command(name="faucet", description="Get a free testnet validator bond (one per account)", guild=guild)
    @app_commands.describe(address="Your validator address (tsc1...), from finalis-cli --testnet getBalance")
    async def faucet_cmd(interaction: discord.Interaction, address: str) -> None:
        if interaction.channel_id != channel_id:
            await interaction.response.send_message(f"Please use <#{channel_id}>.", ephemeral=True)
            return
        await interaction.response.defer(thinking=True)
        try:
            reply = await run(faucet.request, str(interaction.user.id), address)
        except Exception:
            logging.exception("request failed")
            reply = "Something went wrong on my side; please try again later."
        await interaction.followup.send(f"{interaction.user.mention} {reply}")

    async def ticker() -> None:
        await client.wait_until_ready()
        channel = client.get_channel(channel_id) or await client.fetch_channel(channel_id)
        while not client.is_closed():
            try:
                for event in await run(faucet.tick):
                    await channel.send(f"<@{event.user_id}> {event.text}")
                    if "failed" in event.text and admin_user_id:
                        await channel.send(f"<@{admin_user_id}> a faucet payment failed; see the bot log.")
            except Exception:
                logging.exception("tick failed")
            await asyncio.sleep(60)

    started = False

    @client.event
    async def on_ready() -> None:
        # on_ready fires again after every reconnect; one payment loop only.
        nonlocal started
        if started:
            return
        started = True
        await tree.sync(guild=guild)
        logging.info("logged in as %s; /faucet synced to guild %s", client.user, guild_id)
        client.loop.create_task(ticker())

    client.run(env("FAUCET_DISCORD_TOKEN"), log_handler=None)


if __name__ == "__main__":
    main()
