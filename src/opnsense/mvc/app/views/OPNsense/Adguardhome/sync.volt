<script>
    $(document).ready(function() {
        const text = {{ t|json_encode }};
        const endpoint = '/api/adguardhome/sync_service/';
        const service = 'adguardhome_sync';

        function display(value) {
            return value === undefined || value === null || value === '' ? '-' : String(value);
        }

        function updateRuntime() {
            ajaxGet(endpoint + 'status', {}, function(data) {
                const runtime = data.runtime || {};
                $('#runtime\\.role').text(
                    runtime.role === 'source' ? text.source :
                    (runtime.role === 'receiver' ? text.receiver : '-')
                );
                $('#runtime\\.local_address').text(display(runtime.local_address));
                $('#runtime\\.peer_address').text(display(runtime.peer_address));
                $('#runtime\\.port').text(display(runtime.port));
                $('#runtime\\.certificate').text(display(runtime.certificate));
                const isSource = runtime.role === 'source';
                $('#row_sync\\.peer_fingerprint').toggle(isSource);
                $('#syncAct').toggle(isSource);
                $('#sync\\.secret').attr(
                    'placeholder',
                    runtime.secret_configured ? text.secret_configured : ''
                );
            });
            updateServiceControlUI(service);
        }

        mapDataToFormUI({'frm_sync_settings': '/api/adguardhome/sync/get'}).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            $('#row_sync\\.peer_fingerprint').hide();
            $('#syncAct').hide();
            updateRuntime();
        });

        $('#generateSecretAct').click(function() {
            const bytes = new Uint8Array(36);
            window.crypto.getRandomValues(bytes);
            const secret = btoa(String.fromCharCode.apply(null, bytes))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');
            $('#sync\\.secret').val(secret).trigger('change');
        });

        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function() {
                const deferred = new $.Deferred();
                saveFormToEndpoint(
                    '/api/adguardhome/sync/set',
                    'frm_sync_settings',
                    function() { deferred.resolve(); },
                    true,
                    function() { deferred.reject(); }
                );
                return deferred;
            },
            onAction: updateRuntime
        });

        $('#syncAct').SimpleActionButton({
            onAction: updateRuntime
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#runtime">{{ t['runtime'] }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': syncForm, 'id': 'frm_sync_settings']) }}
    </div>
    <div id="runtime" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': statusForm, 'id': 'frm_sync_status']) }}
    </div>
</div>

<section class="grid-bottom-reserve __mt">
    <div class="alert content-box" style="display: flex; align-items: center; margin-bottom: 0;">
        <button class="btn btn-primary __mr" id="reconfigureAct"
            data-endpoint="/api/adguardhome/sync_service/reconfigure"
            data-label="{{ t['save_apply'] }}"
            data-error-title="{{ t['apply_error'] }}"
            type="button">
        </button>
        <button class="btn btn-default __mr" id="generateSecretAct" type="button">
            <i class="fa fa-key fa-fw"></i> {{ t['generate_secret'] }}
        </button>
        <button class="btn btn-default __mr" id="syncAct"
            data-endpoint="/api/adguardhome/sync_service/sync"
            data-label="{{ t['sync_now'] }}"
            data-error-title="{{ t['sync_error'] }}"
            type="button">
        </button>
        <a class="btn btn-default" href="/ui/diagnostics/log/core/adguardhome-sync">
            <i class="fa fa-file-text-o fa-fw"></i> {{ lang._('Log File') }}
        </a>
    </div>
</section>
