const core = require('@actions/core');
const child_process = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const { homePath, sshAgentCmd, sshAddCmd, sshKeyGenCmd, gitCmd } = require('./paths.js');

try {
    const privateKeys = core.getInput('ssh-private-keys', { required: true });
    const logPublicKey = core.getBooleanInput('log-public-key');

    if (!privateKeys) {
        throw new Error("The ssh-private-keys {name: key} argument is empty. Maybe the secret has not been configured, or you are using a wrong secret name in your workflow file.")
    }

    console.debug(privateKeys.replaceAll("\n", ""))
    const privateKeysData = JSON.parse(privateKeys.replaceAll("\n", ""))

    const homeSsh = homePath + '/.ssh';

    console.log(`Adding GitHub.com keys to ${homeSsh}/known_hosts`);

    fs.mkdirSync(homeSsh, { recursive: true });
    fs.appendFileSync(`${homeSsh}/known_hosts`, '\ngithub.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=\n');
    fs.appendFileSync(`${homeSsh}/known_hosts`, '\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n');
    fs.appendFileSync(`${homeSsh}/known_hosts`, '\ngithub.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\n');

    console.log("Starting ssh-agent");

    const authSock = core.getInput('ssh-auth-sock');
    const sshAgentArgs = (authSock && authSock.length > 0) ? ['-a', authSock] : [];

    // Extract auth socket path and agent pid and set them as job variables
    child_process.execFileSync(sshAgentCmd, sshAgentArgs).toString().split("\n").forEach((line) => {
        const matches = /^(SSH_AUTH_SOCK|SSH_AGENT_PID)=(.*); export \1/.exec(line);

        if (matches && matches.length > 0) {
            // This will also set process.env accordingly, so changes take effect for this script
            core.exportVariable(matches[1], matches[2])
            console.log(`${matches[1]}=${matches[2]}`);
        }
    });

    console.log("Adding private key(s) to agent and Configuring deployment key(s)");

    Object.keys(privateKeysData).forEach(async (name) => {
        const repoName = name.trim();
        let privateKey = privateKeysData[name].trim();

        if (!privateKey) {
            throw new Error('privateKey is empty for "' + name + '"')
        }

        privateKey = privateKey.replace(/(KEY-----)(...)/, '$1\n$2')
                  .replace(/(...)(-----END )/, '$1\n$2') + "\n"

        child_process.execFileSync(sshAddCmd, ['-'], { input: privateKey });

        const sha256 = crypto.createHash('sha256').update(privateKey).digest('hex');
        const filename = `${homeSsh}/key-${sha256}`

        await fs.writeFile(filename, privateKey, { }, (err) => {
            if (err) {
                console.log(err)
                return
            }

            fs.chmodSync(filename, '600')

            const parts = repoName.match(/\bgithub\.com[:/]([_.a-z0-9-]+\/[_.a-z0-9-]+)/i);

            if (!parts) {
                if (logPublicKey) {
                    console.log(`Comment for name '${repoName}' does not match GitHub URL pattern. Not treating it as a GitHub deploy key.`);
                }

                return;
            }

            const ownerAndRepo = parts[1].replace(/\.git$/, '');

            child_process.execSync(`${gitCmd} config --global --replace-all url."git@key-${sha256}.github.com:${ownerAndRepo}".insteadOf "https://github.com/${ownerAndRepo}"`);
            child_process.execSync(`${gitCmd} config --global --add url."git@key-${sha256}.github.com:${ownerAndRepo}".insteadOf "git@github.com:${ownerAndRepo}"`);
            child_process.execSync(`${gitCmd} config --global --add url."git@key-${sha256}.github.com:${ownerAndRepo}".insteadOf "ssh://git@github.com/${ownerAndRepo}"`);

            const sshConfig = `\nHost key-${sha256}.github.com\n`
                              + `    HostName github.com\n`
                              + `    IdentityFile ${filename}\n`
                              + `    IdentitiesOnly yes\n`;

            fs.appendFileSync(`${homeSsh}/config`, sshConfig);

            console.log(`Added deploy-key mapping: Use identity '${homeSsh}/key-${sha256}' for GitHub repository ${ownerAndRepo}`);
        })
    });

    console.log("Key(s) added:");

    child_process.execFileSync(sshAddCmd, ['-l'], { stdio: 'inherit' });
} catch (error) {

    if (error.code === 'ENOENT') {
        console.log(`The '${error.path}' executable could not be found. Please make sure it is on your PATH and/or the necessary packages are installed.`);
        console.log(`PATH is set to: ${process.env.PATH}`);
    }

    if (error.constructor && error.constructor.name === 'SyntaxError') {
        console.error(`JSON parsing error on "ssh-private-keys" value: ${error.message}`);
    }

    core.setFailed(error.message);
}
