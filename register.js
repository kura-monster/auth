const { REST, Routes, ApplicationCommandOptionType, PermissionFlagsBits } = require('discord.js');

const ADMIN_ONLY = String(PermissionFlagsBits.Administrator);

const commands = [
  {
    name: 'auth',
    description: 'Discordアカウント認証および接続チェックを行う埋め込みを設置します',
    default_member_permissions: ADMIN_ONLY,
    dm_permission: false
  },
  {
    name: 'lol',
    description: '特定のサーバーを拒否設定に追加/削除します (トグル)',
    default_member_permissions: ADMIN_ONLY,
    dm_permission: false,
    options: [
      {
        name: 'id',
        description: '拒否するサーバー (ギルド) のID',
        type: ApplicationCommandOptionType.String,
        required: true,
        min_length: 17,
        max_length: 20
      }
    ]
  },
  {
    name: 'lollist',
    description: '現在拒否設定中のサーバー一覧を表示します',
    default_member_permissions: ADMIN_ONLY,
    dm_permission: false
  },
  {
    name: 'authstats',
    description: '認証ゲートウェイの稼働状況とブロック統計を表示します',
    default_member_permissions: ADMIN_ONLY,
    dm_permission: false
  }
];

async function registerCommands(clientId, token, guildId) {
  const rest = new REST({ version: '10' }).setToken(token);

  if (guildId) {
    try {
      await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body: commands });
      console.log(`[Register] Guild commands registered for Guild: ${guildId}`);
      return;
    } catch (err) {
      console.warn(`[Register] Guild registration failed (${err.message}), falling back to global...`);
    }
  }

  await rest.put(Routes.applicationCommands(clientId), { body: commands });
  console.log('[Register] Global commands registered. (May take up to 1 hour to propagate)');
}

module.exports = { registerCommands };
