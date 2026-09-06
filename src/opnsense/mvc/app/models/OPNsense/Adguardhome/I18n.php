<?php
namespace OPNsense\Adguardhome;

final class I18n
{
    private const EN = [
        'save_apply' => 'Save and apply',
        'generate_secret' => 'Generate pairing secret',
        'sync_now' => 'Synchronize now',
        'runtime' => 'Runtime',
        'apply_error' => 'Unable to apply synchronization settings',
        'sync_error' => 'Unable to synchronize configuration',
        'source' => 'Configuration source',
        'receiver' => 'Configuration receiver',
        'secret_configured' => 'Configured; leave blank to keep the current secret',
    ];

    private const ZH_CN = [
        'save_apply' => '保存并应用',
        'generate_secret' => '生成配对密钥',
        'sync_now' => '立即同步',
        'runtime' => '运行详情',
        'apply_error' => '无法应用同步设置',
        'sync_error' => '无法同步配置',
        'source' => '配置来源',
        'receiver' => '配置接收方',
        'secret_configured' => '已配置；留空保持当前密钥',
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
        'On the source node, paste the fingerprint shown by the receiver.' => '在配置来源节点填写配置接收方显示的证书指纹。',
        'Role' => '同步角色',
        'Local address' => '本机地址',
        'Peer address' => '对端地址',
        'Port' => '端口',
        'Certificate fingerprint' => '证书指纹',
        'Synchronization certificate fingerprint' => '同步证书指纹',
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
