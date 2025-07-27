from __future__ import annotations

import discord
from discord.ext import commands
from redbot.core import commands as redcommands, Config, checks
from pyrate_limiter import BucketFullException, Duration, RequestRate, Limiter
from typing import Optional

ERROR_MESSAGES = {
    'NOTIF_UNRECOGNIZED': (
        "Notification key not recognized. Use `!notifs info` for valid keys.\n"
        "Valid: kick, ban, mute, jail, warn, channelperms, editchannel, deletemessages, "
        "ratelimit, adminrole, bot"
    ),
    'PERM_UNRECOGNIZED': (
        "Permission key not recognized. Use `!modpset perms info` for valid keys.\n"
        "Valid: kick, ban, mute, jail, warn, channelperms, editchannel, deletemessages"
    )
}

PERM_SYS_INFO = """
**__Permission System Information__**
**Kick:** Can kick members (5 per hour max)
**Ban:** Can ban members (3 per hour max)
**Mute:** Can mute members
**Jail:** Can jail members
**Warn:** Can warn members
**ChannelPerms:** Can add/remove members from channels
**EditChannel:** Can create, rename, enable slowmode and move channels
**DeleteMessages:** Can delete and pin messages (50/hour max)
"""

NOTIF_SYS_INFO = """
**__Notification System Information__**
DM or Channel notifications available:
**Kick, Ban, Mute, Jail, Warn**
**ChannelPerms, EditChannel, DeleteMessages**
**RateLimit (when a mod hits a limit)**
**AdminRole (role gets admin perms)**
**Bot (when a bot joins)**
"""

class ModPlus(commands.Cog):
    """Modernized Ultimate Moderation Cog for RedBot"""
    def __init__(self, bot: commands.Bot):
        self.bot = bot

        self.config = Config.get_conf(self, identifier=8818154, force_registration=True)

        # Rate limits
        self.kicklimiter = Limiter(RequestRate(5, Duration.HOUR))
        self.banlimiter = Limiter(RequestRate(3, Duration.HOUR))

        # Default config
        default_global = {
            'notifs': {k: [] for k in [
                'kick', 'ban', 'mute', 'jail', 'channelperms',
                'editchannel', 'deletemessages', 'ratelimit',
                'adminrole', 'bot', 'warn'
            ]},
            'notifchannels': {k: [] for k in [
                'kick', 'ban', 'mute', 'jail', 'channelperms',
                'editchannel', 'deletemessages', 'ratelimit',
                'adminrole', 'bot', 'warn'
            ]}
        }

        default_guild = {
            'perms': {k: [] for k in [
                'kick', 'ban', 'mute', 'jail', 'channelperms',
                'editchannel', 'deletemessages', 'warn'
            ]},
            'roles': {
                'warning1': None,
                'warning2': None,
                'warning3+': None,
                'jailed': None,
                'muted': None
            }
        }

        self.config.register_guild(**default_guild)
        self.config.register_global(**default_global)

        self.permkeys = list(default_guild['perms'].keys())
        self.notifkeys = list(default_global['notifs'].keys())

    # ====================
    # NOTIFICATION COMMANDS
    # ====================

    @redcommands.group(aliases=['notifs', 'notif'])
    @checks.mod()
    async def adminnotifications(self, ctx: redcommands.Context):
        """Configure what notifications to get"""
        pass

    @adminnotifications.group(name='channel')
    async def notifschannel(self, ctx: redcommands.Context):
        """Configure a channel to receive notifications"""
        pass

    @adminnotifications.command(name='info')
    async def notifsinfo(self, ctx: redcommands.Context):
        """Get info about notification system"""
        await ctx.send(NOTIF_SYS_INFO)

    @adminnotifications.command(name='add')
    async def notifsadd(self, ctx: redcommands.Context, notifkey: str, user: Optional[discord.Member] = None):
        """Subscribe to a notification key"""
        user = user or ctx.author
        notifkey = notifkey.lower().strip()

        if notifkey not in self.notifkeys:
            return await ctx.send(ERROR_MESSAGES['NOTIF_UNRECOGNIZED'])

        async with self.config.notifs() as notifs:
            if user.id in notifs[notifkey]:
                return await ctx.send(f"{user.display_name} is already subscribed to {notifkey}.")
            notifs[notifkey].append(user.id)

        await ctx.send(f"{user.display_name} will now be notified for `{notifkey}`.")

    @adminnotifications.command(name='remove')
    async def notifsremove(self, ctx: redcommands.Context, notifkey: str, user: Optional[discord.Member] = None):
        """Unsubscribe from a notification key"""
        user = user or ctx.author
        notifkey = notifkey.lower().strip()

        if notifkey not in self.notifkeys:
            return await ctx.send(ERROR_MESSAGES['NOTIF_UNRECOGNIZED'])

        async with self.config.notifs() as notifs:
            if user.id not in notifs[notifkey]:
                return await ctx.send(f"{user.display_name} is not subscribed to {notifkey}.")
            notifs[notifkey].remove(user.id)

        await ctx.send(f"{user.display_name} will no longer be notified for `{notifkey}`.")

    @adminnotifications.command(name='list')
    async def notifslist(self, ctx: redcommands.Context, user: Optional[discord.Member] = None):
        """Show which notifications you (or someone) are subscribed to"""
        user = user or ctx.author
        data = await self.config.notifs()
        subscribed = [k for k, v in data.items() if user.id in v]

        if not subscribed:
            return await ctx.send(f"{user.display_name} has no active notifications.")
        await ctx.send(f"{user.display_name} is subscribed to: **{', '.join(subscribed)}**")

    # Channel notifications
    @notifschannel.command(name='add')
    async def channelnotifsadd(self, ctx: redcommands.Context, notifkey: str, channel: discord.TextChannel):
        """Subscribe a channel to a notification key"""
        notifkey = notifkey.lower().strip()

        if notifkey not in self.notifkeys:
            return await ctx.send(ERROR_MESSAGES['NOTIF_UNRECOGNIZED'])

        async with self.config.notifchannels() as channels:
            keylist = channels[notifkey]
            channeldata = [channel.guild.id, channel.id]

            if channeldata in keylist:
                return await ctx.send(f"{channel.name} is already subscribed to {notifkey}.")

            keylist.append(channeldata)

        await ctx.send(f"{channel.name} will now receive `{notifkey}` notifications.")

    @notifschannel.command(name='remove')
    async def channelnotifsremove(self, ctx: redcommands.Context, notifkey: str, channel: discord.TextChannel):
        """Unsubscribe a channel from a notification key"""
        notifkey = notifkey.lower().strip()

        if notifkey not in self.notifkeys:
            return await ctx.send(ERROR_MESSAGES['NOTIF_UNRECOGNIZED'])

        async with self.config.notifchannels() as channels:
            keylist = channels[notifkey]
            channeldata = [channel.guild.id, channel.id]

            if channeldata not in keylist:
                return await ctx.send(f"{channel.name} isn’t subscribed to {notifkey}.")
            keylist.remove(channeldata)

        await ctx.send(f"{channel.name} will no longer receive `{notifkey}` notifications.")

    @notifschannel.command(name='list')
    async def channelnotifslist(self, ctx: redcommands.Context, channel: discord.TextChannel):
        """List notifications for a channel"""
        data = await self.config.notifchannels()
        channeldata = [channel.guild.id, channel.id]
        subscribed = [k for k, v in data.items() if channeldata in v]

        if not subscribed:
            return await ctx.send(f"{channel.name} has no active notifications.")
        await ctx.send(f"{channel.name} is subscribed to: **{', '.join(subscribed)}**")

    # ================
    # NOTIFY FUNCTION
    # ================
    async def notify(self, notifkey: str, payload: str):
        """Send notifications to users & channels"""
        data = await self.config.all()

        # Notify users
        for uid in data['notifs'][notifkey]:
            try:
                user = await self.bot.fetch_user(uid)
                await user.send(payload)
            except discord.Forbidden:
                self.bot.logger.warning(f"Cannot DM user {uid} for {notifkey}")
            except Exception as e:
                self.bot.logger.error(f"Error DMing user {uid}: {e}")

        # Notify channels
        for guild_id, chan_id in data['notifchannels'][notifkey]:
            guild = self.bot.get_guild(guild_id)
            if guild:
                channel = guild.get_channel(chan_id)
                if channel:
                    try:
                        await channel.send(payload, allowed_mentions=discord.AllowedMentions.all())
                    except Exception as e:
                        self.bot.logger.error(f"Error notifying {channel.id} for {notifkey}: {e}")

    # ====================
    # ADMIN LISTENERS
    # ====================
    @commands.Cog.listener(name='on_guild_role_update')
    async def role_add_admin(self, old: discord.Role, new: discord.Role):
        if new.permissions.administrator and not old.permissions.administrator:
            await self.notify('adminrole', f"@everyone Role {new.mention} now has admin perms in **{old.guild.name}** ({old.guild.id})")

    @commands.Cog.listener(name='on_member_join')
    async def join_bot(self, member: discord.Member):
        if member.bot:
            await self.notify('bot', f"@everyone Bot {member.mention} joined **{member.guild.name}** ({member.guild.id})")

    @commands.Cog.listener(name='on_member_update')
    async def member_admin(self, old: discord.Member, new: discord.Member):
        new_roles = [r for r in new.roles if r not in old.roles]
        for role in new_roles:
            if role.permissions.administrator:
                await self.notify('adminrole', f"@everyone {new.mention} gained admin perms via {role.mention} in **{old.guild.name}**")

    # ====================
    # RATE LIMIT HANDLING
    # ====================
    async def rate_limit_exceeded(self, user: discord.Member, action_type: str):
        """Remove mod roles when exceeding rate limits"""
        guild_data = await self.config.guild(user.guild).perms()
        allmodroles = {r for roles in guild_data.values() for r in roles}

        removed, failed = [], []
        for role in user.roles:
            if role.id in allmodroles:
                try:
                    await user.remove_roles(role, reason='Rate limit exceeded.')
                    removed.append(f"{role.mention}({role.id})")
                except discord.Forbidden:
                    failed.append(f"{role.mention}({role.id})")

        if failed:
            await self.notify('ratelimit', f"Failed to remove: {', '.join(failed)}")

        await self.notify('ratelimit',
            f"@everyone {action_type} ratelimit exceeded by {user.mention}. Removed: {', '.join(removed)}"
        )

    async def action_check(self, ctx: redcommands.Context, permkey: str) -> bool:
        """Check if user can run an action + rate limit"""
        if await self.bot.is_admin(ctx.author) or ctx.author.guild_permissions.administrator:
            return True

        perms = await self.config.guild(ctx.guild).perms()
        if not any(r.id in perms[permkey] for r in ctx.author.roles):
            return False

        limiter = self.kicklimiter if permkey == 'kick' else self.banlimiter if permkey == 'ban' else None
        if limiter:
            try:
                limiter.try_acquire(str(ctx.author.id))
            except BucketFullException:
                await self.rate_limit_exceeded(ctx.author, permkey)
                return False
        return True

    # ====================
    # MOD PERMISSION CMDS
    # ====================
    @redcommands.group()
    @checks.admin()
    async def modpset(self, ctx: redcommands.Context):
        """Configure Mod Plus"""
        pass

    @modpset.group(aliases=['perms', 'perm'])
    async def permissions(self, ctx: redcommands.Context):
        """Configure Role Permissions"""
        pass

    @permissions.command(name='info')
    async def permsinfo(self, ctx: redcommands.Context):
        """Get info about perms system"""
        await ctx.send(PERM_SYS_INFO)

    @permissions.command(name='add')
    async def permsadd(self, ctx: redcommands.Context, role: discord.Role, *, permkey: str):
        """Grant a permission key to a role"""
        permkey = permkey.lower().strip()
        if permkey not in self.permkeys:
            return await ctx.send(ERROR_MESSAGES['PERM_UNRECOGNIZED'])

        data = await self.config.guild(ctx.guild).get_raw("perms", permkey)
        if role.id in data:
            return await ctx.send(f"{role.name} already has `{permkey}` permission.")

        data.append(role.id)
        await self.config.guild(ctx.guild).set_raw("perms", permkey, value=data)
        await ctx.send(f"✅ {role.name} was granted `{permkey}` permission.")

    @permissions.command(name='remove')
    async def permsremove(self, ctx: redcommands.Context, role: discord.Role, *, permkey: str):
        """Revoke a permission key from a role"""
        permkey = permkey.lower().strip()
        if permkey not in self.permkeys:
            return await ctx.send(ERROR_MESSAGES['PERM_UNRECOGNIZED'])

        data = await self.config.guild(ctx.guild).get_raw("perms", permkey)
        if role.id not in data:
            return await ctx.send(f"{role.name} doesn’t have `{permkey}` permission.")
        data.remove(role.id)
        await self.config.guild(ctx.guild).set_raw("perms", permkey, value=data)
        await ctx.send(f"✅ `{permkey}` permission revoked from {role.name}.")

    @permissions.group(name='list')
    async def permslist(self, ctx: redcommands.Context):
        """List Permissions"""
        pass

    @permslist.command(name='perm', aliases=['perms', 'permission'])
    async def list_perm_by_perm(self, ctx: redcommands.Context, *, permkey: str):
        """List roles that have a specific permission key"""
        permkey = permkey.lower().strip()
        if permkey not in self.permkeys:
            return await ctx.send(ERROR_MESSAGES['PERM_UNRECOGNIZED'])

        data = await self.config.guild(ctx.guild).get_raw("perms", permkey)
        mentions = [ctx.guild.get_role(r).mention for r in data if ctx.guild.get_role(r)]
        if mentions:
            await ctx.send(f"Roles with `{permkey}`: {', '.join(mentions)}")
        else:
            await ctx.send(f"No roles currently have `{permkey}` permission.")

    @permslist.command(name='role')
    async def list_perms_by_role(self, ctx: redcommands.Context, role: discord.Role):
        """List which permissions a role has"""
        data = await self.config.guild(ctx.guild).perms()
        perms = [k for k, v in data.items() if role.id in v]

        if perms:
            await ctx.send(f"{role.name} has: {', '.join(perms)}")
        else:
            await ctx.send(f"{role.name} has no permissions.")