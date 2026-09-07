<?php
namespace OPNsense\Adguardhome;

final class I18n
{
    private const EN = [
        'save_apply' => 'Save and apply',
        'generate_secret' => 'Generate pairing secret',
        'generate_secret_error' => 'Unable to generate a pairing secret',
        'never' => 'Never',
        'warning_resolver_loopback' => 'The system resolver (/etc/resolv.conf) points to 127.0.0.1, but no DNS service listens there, so this node cannot resolve names itself. Add 127.0.0.1 and ::1 to the DNS listen addresses with port 53, or configure DNS servers under System > Settings > General and disable the local DNS service there.',
        'api_manual_in_use' => 'Own credentials in use; leave empty to switch to the managed account',
        'api_managed_present' => 'Managed account opnsense-ha in use; enter a user to override',
        'api_managed_none' => 'AdGuard Home has no users; the API needs no credentials',
        'api_managed_pending' => 'Managed account will be installed by Save and apply or when this node is CARP backup',
        'conflict_source_won' => 'source kept its values',
        'conflict_receiver_won' => 'receiver values merged back',
        'backup_at' => 'previous file saved as',
        'sync_now' => 'Synchronize now',
        'apply_pending' => 'Apply pending now',
        'runtime' => 'Runtime',
        'apply_error' => 'Unable to apply synchronization settings',
        'sync_error' => 'Unable to synchronize configuration',
        'apply_pending_error' => 'Unable to apply the pending configuration',
        'source' => 'Configuration source',
        'receiver' => 'Configuration receiver',
        'secret_configured' => 'Configured; leave blank to keep the current secret',
        'api_password_configured' => 'Configured; leave blank to keep the current password',
        'mode_hot' => 'API hot update',
        'mode_hot_managed' => 'API hot update (managed account)',
        'mode_hot_manual' => 'API hot update (manual credentials)',
        'mode_hot_open' => 'API hot update (no authentication)',
        'mode_file' => 'File replacement and restart',
        'mode_file_pending' => 'File replacement (managed account not installed yet — select Save and apply)',
        'pending_yes' => 'Yes – waiting for CARP backup state',
        'pending_no' => 'No',
        'result_hot' => 'Applied through the API',
        'result_updated' => 'Updated',
        'result_unchanged' => 'Unchanged',
        'result_staged' => 'Staged for the next backup state',
        'result_failed' => 'Failed',
    ];

    private const ZH_CN = [
        'save_apply' => '保存并应用',
        'generate_secret' => '生成配对密钥',
        'generate_secret_error' => '无法生成配对密钥',
        'never' => '从未',
        'warning_resolver_loopback' => '系统解析器（/etc/resolv.conf）指向 127.0.0.1，但没有任何 DNS 服务在该地址监听，本机自身无法解析域名。请把 127.0.0.1 与 ::1 加入 DNS 监听地址并使用 53 端口，或在 System > Settings > General 中配置 DNS 服务器并停用本地 DNS 服务。',
        'api_manual_in_use' => '正在使用自定义凭据；留空则切换为托管账号',
        'api_managed_present' => '正在使用托管账号 opnsense-ha；填写用户名可覆盖',
        'api_managed_none' => 'AdGuard Home 未设置用户，API 无需凭据',
        'api_managed_pending' => '托管账号将在「保存并应用」或本机成为 CARP 备机时自动安装',
        'conflict_source_won' => '保留了源端的值',
        'conflict_receiver_won' => '采用了接收端的值',
        'backup_at' => '原文件已保存为',
        'sync_now' => '立即同步',
        'apply_pending' => '立即应用待处理配置',
        'runtime' => '运行详情',
        'apply_error' => '无法应用同步设置',
        'sync_error' => '无法同步配置',
        'apply_pending_error' => '无法应用待处理配置',
        'source' => '配置来源',
        'receiver' => '配置接收方',
        'secret_configured' => '已配置；留空保持当前密钥',
        'api_password_configured' => '已配置；留空保持当前密码',
        'mode_hot' => 'API 热更新',
        'mode_hot_managed' => 'API 热更新（插件托管账号）',
        'mode_hot_manual' => 'API 热更新（手工填写的凭据）',
        'mode_hot_open' => 'API 热更新（无需认证）',
        'mode_file' => '替换配置文件并重启',
        'mode_file_pending' => '替换配置文件（托管账号尚未安装 — 请点击“保存并应用”）',
        'pending_yes' => '是 — 等待本机成为 CARP 备用节点',
        'pending_no' => '否',
        'result_hot' => '已通过 API 应用',
        'result_updated' => '已更新',
        'result_unchanged' => '无变化',
        'result_staged' => '已暂存，等待成为备用节点',
        'result_failed' => '失败',
    ];

    private const FORM_ZH_CN = [
        'Enable AdGuard Home' => '启用 AdGuard Home',
        'Start AdGuard Home automatically and make the DNS service available.' => '自动启动 AdGuard Home 并提供 DNS 服务。',
        'DNS listen addresses' => 'DNS 监听地址',
        'Enter one or more IPv4 or IPv6 addresses.' => '输入一个或多个 IPv4 或 IPv6 地址。',
        'Select an available address or enter an IPv4 or IPv6 address.' => '选择可用地址，或输入 IPv4 或 IPv6 地址。',
        'DNS listen port' => 'DNS 监听端口',
        'DNS normally uses port 53.' => 'DNS 通常使用 53 端口。',
        'Enable configuration synchronization' => '启用配置同步',
        'Synchronize AdGuard Home settings through the dedicated state-sync network.' => '通过专用状态同步网络同步 AdGuard Home 设置。',
        'Synchronization port' => '同步端口',
        'The same unused port is used by both nodes.' => '两台节点使用相同的未占用端口。',
        'Pairing secret' => '配对密钥',
        'Use the same newly generated secret on both nodes. It is never shown after saving.' => '在两台节点填写同一段新生成的密钥；保存后不会再次显示。',
        'Peer certificate fingerprint' => '对端证书指纹',
        'Optional on the source node. Leave empty to learn and remember the receiver fingerprint automatically, or paste the fingerprint shown by the receiver.' => '在配置来源节点为可选项。留空时会自动获取并记住配置接收方的证书指纹，也可直接填写接收方显示的指纹。',
        'AdGuard Home API user' => 'AdGuard Home API 用户',
        "Optional. Leave empty to let the plugin manage a dedicated 'opnsense-ha' administrator derived from the pairing secret. Enter a user here to use your own credentials instead." => '可选项。留空时由插件自动管理一个由配对密钥派生的专用管理员账号 opnsense-ha；如需使用自己的凭据，请在此填写用户名。',
        'AdGuard Home API password' => 'AdGuard Home API 密码',
        'Never shown after saving; leave empty to keep the current password.' => '保存后不会再次显示；留空保持当前密码。',
        'Apply changes through the AdGuard Home API' => '通过 AdGuard Home API 应用变更',
        'Apply synchronized changes without restarting AdGuard Home whenever the local API supports them. Uses the managed opnsense-ha account unless credentials are entered above.' => '在本机 API 支持的范围内直接应用同步变更，无需重启 AdGuard Home。未在上方填写凭据时使用托管账号 opnsense-ha。',
        'Defer restarts while CARP master' => '本机为 CARP 主用节点时延迟重启',
        'If a change requires restarting AdGuard Home and this node currently owns the DNS CARP address, stage the change and apply it when the node becomes backup or when Apply pending is selected.' => '如果某项变更需要重启 AdGuard Home，而本机当前持有 DNS CARP 地址，则先暂存该变更，待本机变为备用节点或手动选择“立即应用待处理配置”时再应用。',
        'Role' => '同步角色',
        'Local address' => '本机地址',
        'Peer address' => '对端地址',
        'Port' => '端口',
        'Certificate fingerprint' => '证书指纹',
        'Synchronization certificate fingerprint' => '同步证书指纹',
        'Learned peer fingerprint' => '已学习的对端指纹',
        'Update mode' => '更新方式',
        'Last synchronization result' => '最近一次同步结果',
        'Pending configuration' => '待处理配置',
        'Receiver changes merged back' => '最近回流的接收端修改',
        'Last conflict' => '最近一次冲突',
        'Local changes replaced' => '被覆盖的本地修改',
    ];

    public static function catalog(string $locale): array
    {
        return str_starts_with($locale, 'zh_CN') ? array_replace(self::EN, self::ZH_CN) : self::EN;
    }

    public static function translateForm(array $form, string $locale): array
    {
        if (!str_starts_with($locale, 'zh_CN')) {
            return $form;
        }
        return self::walk($form);
    }

    private static function walk(array $node): array
    {
        foreach ($node as $key => $value) {
            if (is_array($value)) {
                $node[$key] = self::walk($value);
            } elseif (in_array($key, ['label', 'help', 'hint', 'tab_descr'], true) && isset(self::FORM_ZH_CN[$value])) {
                $node[$key] = self::FORM_ZH_CN[$value];
            }
        }
        return $node;
    }
}
