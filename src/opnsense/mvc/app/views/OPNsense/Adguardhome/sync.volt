<script>
    $(document).ready(function() {
        const text = {{ t|json_encode }};
        const endpoint = '/api/adguardhome/sync_service/';
        const service = 'adguardhome_sync';
        let runtime = {};

        function display(value) {
            return value === undefined || value === null || value === '' ? '-' : String(value);
        }

        function resultText(value) {
            if (value === undefined || value === null || value === '') {
                return '-';
            }
            return text['result_' + value] || String(value);
        }

        function modeText() {
            if (!runtime.api_configured || !$('#sync\\.hot_update').is(':checked')) {
                return text.mode_file;
            }
            const state = runtime.api_account_state || '';
            if (state === 'missing' || state === 'stale') {
                // The account is written on the next apply, so until then the
                // receiver replaces the file and restarts AdGuard Home.
                return text.mode_file_pending;
            }
            if (runtime.api_mode === 'manual') {
                return text.mode_hot_manual;
            }
            if (state === 'none') {
                return text.mode_hot_open;
            }
            return state === 'present' ? text.mode_hot_managed : text.mode_hot;
        }

        function describeEvent(event, extra) {
            // Events are {at: epoch seconds, keys: [...]} objects written by the daemon.
            if (!event || !event.at) {
                return text.never;
            }
            const when = new Date(event.at * 1000).toLocaleString();
            const keys = (event.keys || []).slice(0, 8).join(', ') + ((event.keys || []).length > 8 ? ' …' : '');
            const detail = extra ? extra(event) : '';
            return when + (keys ? ' — ' + keys : '') + (detail ? ' (' + detail + ')' : '');
        }

        function updateMode() {
            $('#runtime\\.mode').text(modeText() + (runtime.api_message ? ' — ' + runtime.api_message : ''));
        }

        function updateRuntime() {
            ajaxGet(endpoint + 'status', {}, function(data) {
                runtime = data.runtime || {};
                $('#runtime\\.role').text(
                    runtime.role === 'source' ? text.source :
                    (runtime.role === 'receiver' ? text.receiver : '-')
                );
                $('#runtime\\.local_address').text(display(runtime.local_address));
                $('#runtime\\.peer_address').text(display(runtime.peer_address));
                $('#runtime\\.port').text(display(runtime.port));
                $('#runtime\\.certificate').text(display(runtime.certificate));
                $('#runtime\\.learned_fingerprint').text(display(runtime.learned_fingerprint));
                let lastResult = resultText(runtime.last_result);
                if (runtime.last_error) {
                    lastResult = lastResult + ' (' + runtime.last_error + ')';
                }
                $('#runtime\\.last_result').text(lastResult);
                $('#runtime\\.pending').text(runtime.pending_config ? text.pending_yes : text.pending_no);
                $('#runtime\\.adopted').text(describeEvent(runtime.last_adopted, null));
                $('#runtime\\.conflict').text(describeEvent(runtime.last_conflict, function(event) {
                    return event.winner === 'receiver' ? text.conflict_receiver_won : text.conflict_source_won;
                }));
                $('#runtime\\.overwritten').text(describeEvent(runtime.last_overwritten, function(event) {
                    return event.backup ? text.backup_at + ' ' + event.backup : '';
                }));
                updateMode();
                const isSource = runtime.role === 'source';
                $('#row_sync\\.peer_fingerprint').toggle(isSource);
                $('#syncAct').toggle(isSource);
                $('#applyPendingAct').toggle(!!runtime.pending_config);
                $('#sync\\.secret').attr(
                    'placeholder',
                    runtime.secret_configured ? text.secret_configured : ''
                );
                // Show what is in effect while the fields are empty, like the pairing secret does.
                let accountHint = '';
                if (runtime.api_mode === 'manual') {
                    accountHint = text.api_manual_in_use;
                } else if (runtime.api_account_state === 'present') {
                    accountHint = text.api_managed_present;
                } else if (runtime.api_account_state === 'none') {
                    accountHint = text.api_managed_none;
                } else if (runtime.api_account_state === 'missing' || runtime.api_account_state === 'stale') {
                    accountHint = text.api_managed_pending;
                }
                $('#sync\\.api_username').attr('placeholder', accountHint);
                $('#sync\\.api_password').attr(
                    'placeholder',
                    runtime.api_mode === 'manual' ? text.api_password_configured : accountHint
                );
            });
            updateServiceControlUI(service);
        }

        mapDataToFormUI({'frm_sync_settings': '/api/adguardhome/sync/get'}).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            $('#row_sync\\.peer_fingerprint').hide();
            $('#syncAct').hide();
            $('#applyPendingAct').hide();
            updateRuntime();
        });

        $('#sync\\.hot_update').change(function() {
            updateMode();
        });

        $('#generateSecretAct').click(function() {
            // The secret is generated by the backend CSPRNG and shown once until saved.
            ajaxCall('/api/adguardhome/sync/generate_secret', {}, function(data) {
                if (data && data.status === 'ok' && data.secret) {
                    $('#sync\\.secret').val(data.secret).trigger('change');
                } else {
                    BootstrapDialog.alert({type: BootstrapDialog.TYPE_DANGER, title: text.generate_secret_error,
                                           message: (data && data.message) ? data.message : '-'});
                }
            });
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

        $('#applyPendingAct').SimpleActionButton({
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
        <button class="btn btn-default __mr" id="applyPendingAct"
            data-endpoint="/api/adguardhome/sync_service/apply_pending"
            data-label="{{ t['apply_pending'] }}"
            data-error-title="{{ t['apply_pending_error'] }}"
            type="button">
        </button>
        <a class="btn btn-default" href="/ui/diagnostics/log/core/adguardhome-sync">
            <i class="fa fa-file-text-o fa-fw"></i> {{ lang._('Log File') }}
        </a>
    </div>
</section>
