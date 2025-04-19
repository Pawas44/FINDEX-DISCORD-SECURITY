import discord
from discord.ext import commands
import re
import os
from dotenv import load_dotenv
import logging
import asyncio
from collections import defaultdict, deque
import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(name)s: %(message)s')
logger = logging.getLogger('findex_security')

# Load environment variables
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')

# Define intents
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.guilds = True
intents.members = True

# Create bot instance with command prefix "!"
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Discord invite link pattern
DISCORD_INVITE_PATTERN = re.compile(r'(?:https?://)?(?:www\.)?(?:discord\.(?:gg|io|me|li|com)/[a-zA-Z0-9-_]+)')

# Anti-nuke tracking
class AntiNukeMonitor:
    def __init__(self):
        # Track the number of channels created/deleted by each user
        self.channel_actions = defaultdict(lambda: deque(maxlen=10))
        
        # Track the number of messages sent by each user
        self.message_count = defaultdict(lambda: deque(maxlen=30))
        
        # Track role creations and deletions
        self.role_actions = defaultdict(lambda: deque(maxlen=10))
        
        # Track member ban/kick actions
        self.member_actions = defaultdict(lambda: deque(maxlen=10))
        
        # Thresholds
        self.channel_threshold = 3  # actions within timeframe
        self.message_threshold = 15  # messages within timeframe
        self.role_threshold = 3  # actions within timeframe
        self.member_threshold = 5  # actions within timeframe
        self.timeframe = 10  # seconds

    def add_channel_action(self, user_id):
        self.channel_actions[user_id].append(datetime.datetime.now())
        return self.check_channel_actions(user_id)
    
    def add_message(self, user_id):
        self.message_count[user_id].append(datetime.datetime.now())
        return self.check_message_spam(user_id)
    
    def add_role_action(self, user_id):
        self.role_actions[user_id].append(datetime.datetime.now())
        return self.check_role_actions(user_id)
    
    def add_member_action(self, user_id):
        self.member_actions[user_id].append(datetime.datetime.now())
        return self.check_member_actions(user_id)
    
    def check_channel_actions(self, user_id):
        if len(self.channel_actions[user_id]) < self.channel_threshold:
            return False
            
        # Check if the actions happened within the timeframe
        now = datetime.datetime.now()
        oldest_allowed = now - datetime.timedelta(seconds=self.timeframe)
        
        recent_actions = [action for action in self.channel_actions[user_id] if action > oldest_allowed]
        return len(recent_actions) >= self.channel_threshold
    
    def check_message_spam(self, user_id):
        if len(self.message_count[user_id]) < self.message_threshold:
            return False
            
        now = datetime.datetime.now()
        oldest_allowed = now - datetime.timedelta(seconds=self.timeframe)
        
        recent_messages = [msg for msg in self.message_count[user_id] if msg > oldest_allowed]
        return len(recent_messages) >= self.message_threshold
    
    def check_role_actions(self, user_id):
        if len(self.role_actions[user_id]) < self.role_threshold:
            return False
            
        now = datetime.datetime.now()
        oldest_allowed = now - datetime.timedelta(seconds=self.timeframe)
        
        recent_actions = [action for action in self.role_actions[user_id] if action > oldest_allowed]
        return len(recent_actions) >= self.role_threshold
    
    def check_member_actions(self, user_id):
        if len(self.member_actions[user_id]) < self.member_threshold:
            return False
            
        now = datetime.datetime.now()
        oldest_allowed = now - datetime.timedelta(seconds=self.timeframe)
        
        recent_actions = [action for action in self.member_actions[user_id] if action > oldest_allowed]
        return len(recent_actions) >= self.member_threshold

# Create anti-nuke monitor instance
anti_nuke = AntiNukeMonitor()

# Store a log of actions for audit purposes
audit_log = deque(maxlen=100)

async def log_action(guild, action, user=None, target=None, reason=None):
    """Log actions to audit log and console"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_str = f"{user.name}#{user.discriminator} ({user.id})" if user else "System"
    target_str = f"{target.name}#{target.discriminator} ({target.id})" if isinstance(target, discord.User) or isinstance(target, discord.Member) else str(target)
    
    log_entry = f"[{timestamp}] {action} | User: {user_str} | Target: {target_str} | Reason: {reason}"
    audit_log.append(log_entry)
    logger.info(log_entry)
    
    # Try to send to audit log channel if configured
    audit_channel_id = None  # You could make this configurable per guild
    if audit_channel_id:
        try:
            channel = guild.get_channel(audit_channel_id)
            if channel:
                await channel.send(f"```{log_entry}```")
        except Exception as e:
            logger.error(f"Failed to send to audit log channel: {e}")

async def handle_raid_attempt(guild, user, reason):
    """Handle detected raid attempts"""
    try:
        # Remove all permissions from the user
        if isinstance(user, discord.Member):
            await log_action(guild, "RAID ATTEMPT DETECTED", user=user, reason=reason)
            
            # Try to remove all roles from the user
            for role in user.roles:
                if role != guild.default_role and guild.me.top_role > role:
                    try:
                        await user.remove_roles(role, reason="Automatic role removal due to raid attempt")
                    except discord.Forbidden:
                        logger.warning(f"Cannot remove role {role.name} from {user}")
            
            # Ban the user
            try:
                await guild.ban(user, reason=f"Automatic ban due to raid attempt: {reason}")
                await log_action(guild, "AUTOMATIC BAN", user=bot.user, target=user, reason=f"Raid attempt: {reason}")
            except discord.Forbidden:
                logger.warning(f"Cannot ban user {user}")
                
            # Send notification to owner and other admins
            try:
                await guild.owner.send(f"⚠️ **RAID ALERT** ⚠️\nPotential raid detected in {guild.name}!\nUser: {user.mention} ({user.id})\nReason: {reason}")
            except:
                pass
            
            # Send to a log channel if available
            log_channels = [channel for channel in guild.text_channels if "log" in channel.name.lower()]
            if log_channels:
                try:
                    await log_channels[0].send(f"⚠️ **RAID ALERT** ⚠️\nPotential raid detected!\nUser: {user.mention} ({user.id})\nReason: {reason}")
                except:
                    pass
    except Exception as e:
        logger.error(f"Error handling raid attempt: {e}")

@bot.event
async def on_ready():
    logger.info(f'{bot.user.name} has connected to Discord!')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="for server security"))

@bot.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == bot.user:
        return
    
    # Check if message contains Discord invite links and sender is not an admin
    if not message.author.guild_permissions.administrator:
        if DISCORD_INVITE_PATTERN.search(message.content):
            await message.delete()
            warning = await message.channel.send(f"{message.author.mention}, posting server invite links is not allowed!")
            # Delete the warning message after 5 seconds
            await warning.delete(delay=5)
            logger.info(f'Deleted invite link from {message.author} in {message.channel}')
            
            # Add to anti-nuke tracking
            is_spam = anti_nuke.add_message(message.author.id)
            if is_spam:
                await handle_raid_attempt(message.guild, message.author, "Message spam detected")
            
            return
    
    # Anti-spam check
    if not message.author.guild_permissions.administrator:
        is_spam = anti_nuke.add_message(message.author.id)
        if is_spam:
            await handle_raid_attempt(message.guild, message.author, "Message spam detected")
            return
    
    # Process commands
    await bot.process_commands(message)

@bot.event
async def on_guild_channel_create(channel):
    """Monitor channel creation for potential nukes"""
    async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create):
        user = entry.user
        if user == bot.user:
            return
            
        await log_action(channel.guild, "CHANNEL CREATED", user=user, target=channel)
        
        # Check if this user has been creating many channels quickly
        if not user.guild_permissions.administrator:
            is_raid = anti_nuke.add_channel_action(user.id)
            if is_raid:
                await handle_raid_attempt(channel.guild, user, "Mass channel creation detected")

@bot.event
async def on_guild_channel_delete(channel):
    """Monitor channel deletion for potential nukes"""
    async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
        user = entry.user
        if user == bot.user:
            return
            
        await log_action(channel.guild, "CHANNEL DELETED", user=user, target=channel)
        
        # Check if this user has been deleting many channels quickly
        if not user.guild_permissions.administrator:
            is_raid = anti_nuke.add_channel_action(user.id)
            if is_raid:
                await handle_raid_attempt(channel.guild, user, "Mass channel deletion detected")

@bot.event
async def on_guild_role_create(role):
    """Monitor role creation for potential nukes"""
    async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_create):
        user = entry.user
        if user == bot.user:
            return
            
        await log_action(role.guild, "ROLE CREATED", user=user, target=role)
        
        # Check if this user has been creating many roles quickly
        if not user.guild_permissions.administrator:
            is_raid = anti_nuke.add_role_action(user.id)
            if is_raid:
                await handle_raid_attempt(role.guild, user, "Mass role creation detected")

@bot.event
async def on_guild_role_delete(role):
    """Monitor role deletion for potential nukes"""
    async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
        user = entry.user
        if user == bot.user:
            return
            
        await log_action(role.guild, "ROLE DELETED", user=user, target=role)
        
        # Check if this user has been deleting many roles quickly
        if not user.guild_permissions.administrator:
            is_raid = anti_nuke.add_role_action(user.id)
            if is_raid:
                await handle_raid_attempt(role.guild, user, "Mass role deletion detected")

@bot.event
async def on_member_ban(guild, user):
    """Monitor bans for potential nukes"""
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
        if entry.target.id == user.id:
            moderator = entry.user
            if moderator == bot.user:
                return
                
            await log_action(guild, "MEMBER BANNED", user=moderator, target=user)
            
            # Check if this user has been banning many members quickly
            if not moderator.guild_permissions.administrator:
                is_raid = anti_nuke.add_member_action(moderator.id)
                if is_raid:
                    await handle_raid_attempt(guild, moderator, "Mass banning detected")

@bot.command(name="purge")
@commands.has_permissions(administrator=True)
async def purge_user_messages(ctx, user: discord.Member, limit: int = 100):
    """Delete a specified number of messages from a user in all channels"""
    success_count = 0
    
    for channel in ctx.guild.text_channels:
        try:
            # Skip channels the bot can't access
            if not channel.permissions_for(ctx.guild.me).manage_messages:
                continue
                
            deleted = await channel.purge(limit=limit, check=lambda m: m.author == user)
            success_count += len(deleted)
        except discord.Forbidden:
            pass
        except Exception as e:
            logger.error(f"Error purging messages in {channel}: {e}")
    
    response = await ctx.send(f"Deleted {success_count} messages from {user.mention}.")
    await response.delete(delay=10)
    await log_action(ctx.guild, "MESSAGES PURGED", user=ctx.author, target=user, reason=f"{success_count} messages deleted")

@bot.command(name="ban")
@commands.has_permissions(administrator=True)
async def ban_user(ctx, user: discord.Member, *, reason=None):
    """Ban a user from the server"""
    if reason is None:
        reason = "No reason provided"
    
    await ctx.guild.ban(user, reason=reason)
    await ctx.send(f"{user.mention} has been banned. Reason: {reason}")
    await log_action(ctx.guild, "MEMBER BANNED", user=ctx.author, target=user, reason=reason)

@bot.command(name="kick")
@commands.has_permissions(administrator=True)
async def kick_user(ctx, user: discord.Member, *, reason=None):
    """Kick a user from the server"""
    if reason is None:
        reason = "No reason provided"
    
    await ctx.guild.kick(user, reason=reason)
    await ctx.send(f"{user.mention} has been kicked. Reason: {reason}")
    await log_action(ctx.guild, "MEMBER KICKED", user=ctx.author, target=user, reason=reason)

@bot.command(name="clean")
@commands.has_permissions(manage_messages=True)
async def clean_messages(ctx, limit: int = 10):
    """Delete a specified number of messages from the channel"""
    deleted = await ctx.channel.purge(limit=limit + 1)  # +1 to include the command itself
    response = await ctx.send(f"Deleted {len(deleted) - 1} messages.")
    await response.delete(delay=5)
    await log_action(ctx.guild, "MESSAGES CLEANED", user=ctx.author, target=ctx.channel, reason=f"{len(deleted) - 1} messages deleted")

@bot.command(name="lockdown")
@commands.has_permissions(administrator=True)
async def lockdown(ctx, *, reason="Security threat detected"):
    """Lock all channels to prevent messages from being sent"""
    default_role = ctx.guild.default_role
    
    locked_channels = 0
    for channel in ctx.guild.text_channels:
        try:
            # Skip channels the bot can't access
            if not channel.permissions_for(ctx.guild.me).manage_channels:
                continue
                
            # Lock the channel by removing send permissions for @everyone
            overwrites = channel.overwrites_for(default_role)
            if not overwrites.send_messages is False:
                overwrites.send_messages = False
                await channel.set_permissions(default_role, overwrite=overwrites)
                locked_channels += 1
        except Exception as e:
            logger.error(f"Error locking channel {channel}: {e}")
    
    await ctx.send(f"🔒 Server lockdown enabled! {locked_channels} channels have been locked.\nReason: {reason}")
    await log_action(ctx.guild, "SERVER LOCKDOWN", user=ctx.author, reason=reason)

@bot.command(name="unlock")
@commands.has_permissions(administrator=True)
async def unlock(ctx):
    """Unlock all channels after a lockdown"""
    default_role = ctx.guild.default_role
    
    unlocked_channels = 0
    for channel in ctx.guild.text_channels:
        try:
            # Skip channels the bot can't access
            if not channel.permissions_for(ctx.guild.me).manage_channels:
                continue
                
            # Check if the channel has @everyone permissions modified
            overwrites = channel.overwrites_for(default_role)
            if overwrites.send_messages is False:
                # Reset send_messages to None (default)
                overwrites.send_messages = None
                
                # If the overwrite becomes empty, remove it entirely
                if overwrites.is_empty():
                    await channel.set_permissions(default_role, overwrite=None)
                else:
                    await channel.set_permissions(default_role, overwrite=overwrites)
                    
                unlocked_channels += 1
        except Exception as e:
            logger.error(f"Error unlocking channel {channel}: {e}")
    
    await ctx.send(f"🔓 Server lockdown disabled! {unlocked_channels} channels have been unlocked.")
    await log_action(ctx.guild, "SERVER UNLOCK", user=ctx.author)

@bot.command(name="antinuke")
@commands.has_permissions(administrator=True)
async def antinuke_settings(ctx, setting=None, value=None):
    """Configure anti-nuke settings"""
    if setting is None:
        # Display current settings
        embed = discord.Embed(
            title="Anti-Nuke Settings",
            description="Current anti-nuke protection settings:",
            color=discord.Color.blue()
        )
        
        embed.add_field(name="Channel Action Threshold", value=f"{anti_nuke.channel_threshold} actions", inline=True)
        embed.add_field(name="Message Threshold", value=f"{anti_nuke.message_threshold} messages", inline=True)
        embed.add_field(name="Role Action Threshold", value=f"{anti_nuke.role_threshold} actions", inline=True)
        embed.add_field(name="Member Action Threshold", value=f"{anti_nuke.member_threshold} actions", inline=True)
        embed.add_field(name="Timeframe", value=f"{anti_nuke.timeframe} seconds", inline=True)
        
        await ctx.send(embed=embed)
        return
    
    if setting not in ["channel", "message", "role", "member", "timeframe"]:
        await ctx.send("Invalid setting. Available settings: channel, message, role, member, timeframe")
        return
    
    if value is None:
        await ctx.send("Please provide a value for the setting.")
        return
    
    try:
        value = int(value)
        if value <= 0:
            await ctx.send("Value must be greater than 0.")
            return
            
        if setting == "channel":
            anti_nuke.channel_threshold = value
        elif setting == "message":
            anti_nuke.message_threshold = value
        elif setting == "role":
            anti_nuke.role_threshold = value
        elif setting == "member":
            anti_nuke.member_threshold = value
        elif setting == "timeframe":
            anti_nuke.timeframe = value
            
        await ctx.send(f"Anti-nuke {setting} threshold set to {value}.")
        await log_action(ctx.guild, "ANTINUKE SETTING CHANGED", user=ctx.author, target=setting, reason=f"Value set to {value}")
        
    except ValueError:
        await ctx.send("Value must be a number.")

@bot.command(name="auditlog")
@commands.has_permissions(administrator=True)
async def show_audit_log(ctx, entries: int = 10):
    """Show recent audit log entries from the bot"""
    if entries > 50:
        entries = 50  # Cap at 50 to avoid large messages
        
    if len(audit_log) == 0:
        await ctx.send("No audit log entries yet.")
        return
        
    # Get the most recent entries, up to the requested number
    recent_entries = list(audit_log)[-entries:]
    
    # Split into chunks if necessary (Discord has a 2000 character limit)
    chunks = []
    current_chunk = "```"
    
    for entry in recent_entries:
        # If adding this entry would exceed the limit, start a new chunk
        if len(current_chunk) + len(entry) + 4 > 1990:  # 4 for the ``` at the end
            current_chunk += "```"
            chunks.append(current_chunk)
            current_chunk = "```"
            
        current_chunk += entry + "\n"
    
    # Add the last chunk if it has content
    if current_chunk != "```":
        current_chunk += "```"
        chunks.append(current_chunk)
    
    # Send all chunks
    for i, chunk in enumerate(chunks):
        await ctx.send(f"Audit Log (Part {i+1}/{len(chunks)}):\n{chunk}")

@bot.command(name="help")
async def help_command(ctx):
    """Show help for all commands"""
    embed = discord.Embed(
        title="Findex Security Bot Commands",
        description="Here are the available commands:",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="!purge @user [limit=100]",
        value="Deletes a specified number of messages from a user in all channels (Admin only)",
        inline=False
    )
    embed.add_field(
        name="!ban @user [reason]", 
        value="Bans a user from the server (Admin only)",
        inline=False
    )
    embed.add_field(
        name="!kick @user [reason]", 
        value="Kicks a user from the server (Admin only)",
        inline=False
    )
    embed.add_field(
        name="!clean [limit=10]", 
        value="Deletes a specified number of messages from the current channel (Requires manage messages permission)",
        inline=False
    )
    embed.add_field(
        name="!lockdown [reason]", 
        value="Locks all channels to prevent messages (Admin only)",
        inline=False
    )
    embed.add_field(
        name="!unlock", 
        value="Unlocks all channels after a lockdown (Admin only)",
        inline=False
    )
    embed.add_field(
        name="!antinuke [setting] [value]", 
        value="Configure anti-nuke settings (Admin only)",
        inline=False
    )
    embed.add_field(
        name="!auditlog [entries=10]", 
        value="Show recent security audit log entries (Admin only)",
        inline=False
    )
    
    await ctx.send(embed=embed)

# Error handling
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You don't have permission to use this command.")
    elif isinstance(error, commands.CommandNotFound):
        pass  # Ignore command not found errors
    else:
        logger.error(f"Command error: {error}")

# Run the bot
if __name__ == "__main__":
    bot.run(TOKEN)
