const {
  Client,
  GatewayIntentBits,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  PermissionFlagsBits,
  MessageFlags,
  Events
} = require('discord.js');

const { getBannedGuilds, saveBannedGuilds, isValidGuildId } = require('./bannedGuilds');

function adminRoleIds() {
  return (process.env.ADMIN_ROLE_IDS || '')
    .split(',')
    .map(s => s.trim())
    .filter(isValidGuildId);
}

function authorize(interaction) {
  if (!interaction.inGuild() || !interaction.member) {
    return { ok: false, reason: 'このコマンドはサーバー内でのみ実行できます。' };
  }

  const expectedGuildId = process.env.GUILD_ID;
  if (expectedGuildId && interaction.guildId !== expectedGuildId) {
    return { ok: false, reason: 'このコマンドは、認証を運用しているサーバーでのみ実行できます。' };
  }

  const isAdmin = interaction.memberPermissions?.has(PermissionFlagsBits.Administrator);
  const allowed = adminRoleIds();
  const hasRole = allowed.length > 0 && allowed.some(id => interaction.member.roles.cache.has(id));

  if (!isAdmin && !hasRole) {
    return { ok: false, reason: 'このコマンドは管理者権限、または指定された管理用ロールを持つユーザーのみ実行できます。' };
  }

  return { ok: true };
}

function reply(interaction, content) {
  return interaction.reply({ content, flags: MessageFlags.Ephemeral });
}

function authStartUrl() {
  const { publicBaseUrl } = require('./server');
  return `${publicBaseUrl()}/api/auth/start`;
}

async function handleAuth(interaction) {
  if (!process.env.CLIENT_ID || !process.env.REDIRECT_URI) {
    return reply(interaction, 'システム構成エラー: CLIENT_ID または REDIRECT_URI が設定されていません。');
  }

  const embed = new EmbedBuilder()
    .setColor(0x4f46e5)
    .setTitle('Identity Verification')
    .setDescription(
      'サーバーセキュリティ維持のため、アカウントの連携認証が必要です。\n' +
      '接続元ネットワークの安全確認およびアカウント検証を行います。\n\n' +
      '下のボタンを押して、認証手続きを完了してください。'
    )
    .addFields(
      { name: 'Policy', value: 'VPN、Tor、プロキシ、およびホスティングプロバイダー経由のアクセスは制限されます。', inline: false },
      { name: 'Note', value: '認証は開始から10分以内に完了してください。途中で回線を切り替えるとやり直しになります。', inline: false }
    )
    .setFooter({ text: 'Security Service Control | Supported by Yoah Empire' });

  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setURL(authStartUrl())
      .setLabel('Verify Account')
      .setStyle(ButtonStyle.Link)
  );

  await interaction.reply({ embeds: [embed], components: [row] });
}

async function handleToggleBannedGuild(interaction) {
  const targetGuildId = interaction.options.getString('id').trim();

  if (!isValidGuildId(targetGuildId)) {
    return reply(interaction, '無効な Discord サーバー ID の形式です。数字 17〜20 桁で指定してください。');
  }

  const bannedList = getBannedGuilds();
  const index = bannedList.indexOf(targetGuildId);
  const next = index > -1
    ? bannedList.filter(id => id !== targetGuildId)
    : bannedList.concat(targetGuildId);

  if (!saveBannedGuilds(next)) {
    return reply(interaction, '拒否リストの保存に失敗しました。サーバーのログを確認してください。');
  }

  return reply(
    interaction,
    index > -1
      ? `拒否設定サーバーから削除しました。 ID: \`${targetGuildId}\``
      : `拒否設定サーバーに追加しました。 ID: \`${targetGuildId}\``
  );
}

async function handleListBannedGuilds(interaction) {
  const bannedList = getBannedGuilds();
  if (bannedList.length === 0) {
    return reply(interaction, '現在、拒否設定されているサーバーはありません。');
  }

  const lines = bannedList.map((id, i) => `${i + 1}. \`${id}\``);
  let content = `### 拒否設定中のサーバー一覧 (${bannedList.length}件)\n`;
  for (const line of lines) {
    if (content.length + line.length > 1900) {
      content += `\n…ほか ${bannedList.length - lines.indexOf(line)} 件`;
      break;
    }
    content += line + '\n';
  }

  return reply(interaction, content);
}

async function handleStats(interaction) {
  const { getMetrics } = require('./server');
  const m = getMetrics();

  const embed = new EmbedBuilder()
    .setColor(0x4f46e5)
    .setTitle('認証ゲートウェイ統計')
    .addFields(
      { name: '稼働時間', value: `${Math.floor(m.uptimeSec / 3600)}時間 ${Math.floor((m.uptimeSec % 3600) / 60)}分`, inline: true },
      { name: '開始', value: String(m.started), inline: true },
      { name: '成功', value: String(m.succeeded), inline: true },
      { name: 'ネットワーク拒否', value: String(m.blockedNetwork), inline: true },
      { name: 'チャレンジ拒否', value: String(m.blockedChallenge), inline: true },
      { name: '拒否サーバー所属', value: String(m.blockedGuild), inline: true },
      { name: 'レート制限', value: String(m.blockedRate), inline: true },
      { name: 'state 不正', value: String(m.blockedState), inline: true },
      { name: 'エラー', value: String(m.errors), inline: true },
      { name: 'PoW 難易度', value: `${m.challenge.powBits} bits (期待 ${m.challenge.expectedHashes.toLocaleString()} 回)`, inline: false },
      { name: 'Turnstile', value: m.challenge.turnstile, inline: true },
      { name: '進行中セッション', value: String(m.pendingSessions), inline: true }
    )
    .setTimestamp();

  return interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
}

const HANDLERS = {
  auth: handleAuth,
  lol: handleToggleBannedGuild,
  lollist: handleListBannedGuilds,
  authstats: handleStats
};

function setupBot() {
  const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers]
  });

  client.once(Events.ClientReady, () => {
    console.log(`[Bot] Logged in as ${client.user.tag}`);
    if (adminRoleIds().length === 0) {
      console.warn('[Bot] ADMIN_ROLE_IDS が未設定です。管理コマンドは Administrator 権限を持つユーザーのみ実行できます。');
    }
  });

  client.on(Events.InteractionCreate, async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    const handler = HANDLERS[interaction.commandName];
    if (!handler) return;

    const auth = authorize(interaction);
    if (!auth.ok) return reply(interaction, auth.reason);

    try {
      await handler(interaction);
    } catch (error) {
      console.error(`[Bot] /${interaction.commandName} の実行に失敗:`, error);
      const message = 'コマンドの実行中にエラーが発生しました。';
      if (interaction.replied || interaction.deferred) {
        await interaction.followUp({ content: message, flags: MessageFlags.Ephemeral }).catch(() => {});
      } else {
        await reply(interaction, message).catch(() => {});
      }
    }
  });

  return client;
}

module.exports = { setupBot };
