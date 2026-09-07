{#
 # Copyright (c) 2021 Michael Muenz <m.muenz@max-it.de>
 # All rights reserved.
 #}

<div class="content-box" style="padding-bottom: 1.5em;">
    <div id="dnsWarnings" class="alert alert-warning" style="display:none; margin: 1em;"></div>
    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general_settings'])}}
    <div class="col-md-12">
        <hr />
        <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b> <i id="saveAct_progress"></i></button>
    </div>
</div>

<script>
    $(function() {
        const warningText = {{ t|json_encode }};
        function showWarnings(warnings) {
            const box = $('#dnsWarnings');
            if (!warnings || !warnings.length) { box.hide().empty(); return; }
            box.empty();
            warnings.forEach(function(item) {
                const text = warningText['warning_' + item.code] || item.message;
                box.append($('<div/>').text(text));
            });
            box.show();
        }
        function refreshWarnings() {
            ajaxGet('/api/adguardhome/general/warnings', {}, function(data) { showWarnings(data.warnings); });
        }
        var data_get_map = {'frm_general_settings':"/api/adguardhome/general/get"};
        mapDataToFormUI(data_get_map).done(function(data){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            refreshWarnings();
        });

    updateServiceControlUI('adguardhome');

        $("#saveAct").click(function(){
            saveFormToEndpoint(url="/api/adguardhome/general/set", formid='frm_general_settings',callback_ok=function(){
            $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
                ajaxCall(url="/api/adguardhome/service/reconfigure", sendData={}, callback=function(data,status) {
                    updateServiceControlUI('adguardhome');
                    showWarnings(data && data.warnings ? data.warnings : []);
                    $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                });
            });
        });

    });
</script>
