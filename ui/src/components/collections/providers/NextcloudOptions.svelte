<script>
    import Field from "@/components/base/Field.svelte";

    export let key = "";
    export let config = {};
</script>

<div class="section-title">Nextcloud OIDC Endpoints</div>
<Field class="form-field required" name="{key}.authURL" let:uniqueId>
    <label for={uniqueId}>Auth URL</label>
    <input type="url" id={uniqueId} bind:value={config.authURL} required />
    <div class="help-block">
        Ex. {`https://nextcloud.your.domain/apps/oauth2/authorize`}
    </div>
</Field>
<Field class="form-field required" name="{key}.tokenURL" let:uniqueId>
    <label for={uniqueId}>Token URL</label>
    <input type="url" id={uniqueId} bind:value={config.tokenURL} required />
    <div class="help-block">
        Ex. {`https://nextcloud.your.domain/apps/oauth2/api/v1/token`}
    </div>
</Field>
<Field class="form-field required" name="{key}.userInfoURL" let:uniqueId>
    <label for={uniqueId}>User Info URL</label>
    <input type="url" id={uniqueId} bind:value={config.userInfoURL} required />
    <div class="help-block">
        Ex. {`https://nextcloud.your.domain/ocs/v2.php/cloud/user?format=json`}
    </div>
</Field>
