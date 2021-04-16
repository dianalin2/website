---
title: picoCTF 2021 - BitHug (web)
date: 2021-04-05
slug: /writeups/picoctf-2021-bithug
excerpt: Exploiting SSRF in a complex web application
author: Darin Mao and Daniel Wang
---

BitHug was a web exploitation challenge from picoCTF 2021.

# Description
> Code management software is way too bloated. Try our new lightweight solution, BitHug.

Files:
- [distribution.tgz](https://venus.picoctf.net/static/c634d1be7806c6c19248bdb7dc7d4ea3/distribution.tgz)

We are provided with the full source in `distribution.tgz`, allowing us to audit the source and run an instance locally. The application hosts git repositories via HTTP and it also supports webhooks and user access control.

Trying to see how we get the flag, we search for it in the source.

```typescript
    // Every user gets their own target to attack. Please do not try to
    // attack someone else's target.
    const targetRepo = new GitManager(`_/${user}.git`);
    await targetRepo.create();
    await targetRepo.initializeReadme(`
## Super Secret Admin Repo

The flag is \`${process.env.FLAG ?? "picoCTF{this_is_a_test_flag}"}\`
`);
```

It looks like whenever a new user is created, a private repository we do not have access to is created at `_/${user}.git` with the flag in the README. Thus, our goal is to try to either gain access to this private repository or read its contents directly.

# Access Control
The application will give us access to a git repository `${repoOwner}/${repo}.git` if any of these are true:
- `user.kind` is `admin`
- `user.user` is `repoOwner`
- `repo.getAccessConfig()` contains `user.user`

```typescript
router.use("/:user/:repo.git", async (req, res, next) => {
    const repoOwner = req.params.user;
    const repo = req.params.repo;
    if (!/^[a-zA-Z0-9_-]+$/.exec(repoOwner) || !/^[a-zA-Z0-9_\-\.]+$/.exec(repo)) {
        return res.status(404).end();
    }

    const user = req.user;
    if (user.kind === "none") { throw new Error("unreachable"); }

    const potentialRepo = new GitManager(`${repoOwner}/${repo}.git`);
    if (!await potentialRepo.exists()) {
        return res.status(404).end();
    }

    if (user.kind === "admin" || user.user === repoOwner) {
        req.git = potentialRepo
        return next();
    }

    const configBlob = await potentialRepo.getAccessConfig();
    if (!configBlob) {
        return res.status(404).end();
    }

    const foundUser = configBlob.split("\n").find((name) => name === user.user);
    if (!foundUser) {
        return res.status(404).end();
    }

    req.git = potentialRepo;
    return next();
})
```

Since `repoOwner` is not allowed to be `_`, the second option is impossible. We can explore the other two options.

The only place `user.kind` is set to `admin` is if the request comes from localhost:

```typescript
const sourceIp = req.socket.remoteAddress;
if (sourceIp === "127.0.0.1" || sourceIp === "::1" || sourceIp === "::ffff:127.0.0.1") {
    req.user = { kind: "admin" };
    return next();
}
```

Therefore, we can make requests as `admin` if there is SSRF somewhere else in the application.

`AccessConfig` is a little more interesting. If our username is contained in a special file on a special `meta/config` ref, then we are allowed access:

```typescript
public async getAccessConfig() {
    const hash = await this.resolveRef("refs/meta/config");
    if (!hash) return undefined
    const configCommit = await this.getCommit(hash);
    if (!configCommit) return undefined
    const configTree = await this.getTree(configCommit.tree);
    const configFile = configTree?.find(({ name, mode }) => name === "access.conf" && mode === "file");
    if (!configFile) return undefined
    const configBlob = await this.getBlob(configFile.hash);
    return configBlob;
}
```

If we can commit this file to remote then we can get access to the private repository.

# Webhooks
When we use the `git-receive-pack` endpoint, our webhooks are executed:

```typescript
router.post("/:user/:repo.git/git-receive-pack", async (req, res) => {
    const ref = await req.git.receivePackPost(res, req.body);
    const webhooks = await webhookManager.getWebhooksForRepo(req.git.repo);
    const options = {
        ref,
        branch: ref.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : undefined,
        user: req.user.kind === "user" ? req.user.user : undefined,
        repo: req.git.repo,
    };

    for (let webhook of webhooks) {
        const url =  formatString(webhook.url, options);
        try {
            const body = Buffer.from(formatString(webhook.body.toString("latin1"), options), "latin1");
            await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": webhook.contentType,
                },
                body,
            });
        } catch (e) {
            console.warn("Failed to push webhook", url, e);
        }
    }
});
```

This lets us make arbitrary HTTP POST requests with any body and any content type, which means we can make git requests! If we use this to push commits to the private repository, then the request will come from localhost and be considered `admin`. Unfortunately, there is a bit of validation on the webhooks:

```typescript
router.post("/:user/:repo.git/webhooks", async (req, res) => {
    if (req.user.kind === "admin" || req.user.kind === "none") {
        return res.status(400).end();
    }

    const { url, body, contentType } = req.body;
    const validationUrl = new URL(url);
    if (validationUrl.port !== "" && validationUrl.port !== "80") {
        throw new Error("Url must go to port 80");
    }
    if (validationUrl.host === "localhost" || validationUrl.host === "127.0.0.1") {
        throw new Error("Url must not go to localhost");
    }

    if (typeof contentType !== "string" || typeof body !== "string") {
        throw new Error("Bad arguments");
    }
    const trueBody = Buffer.from(body, "base64");

    await webhookManager.addWebhook(req.git.repo, req.user.user, url, contentType, trueBody);
    return res.send({});
});
```

However, both the URL and body are passed through `formatString` before executing the webhook.

```typescript
const formatString = (data: string, options: Record<string, string | undefined>) => {
    return data.replace(/\{\{[^\}]+\}\}/g, (match) => {
        const option = match.slice(2, -2);
        return options[option] ?? "";
    })
}
```

Notice that if the option does not exist, then the function replaces it with nothing. Hence, we construct a URL like this:

```
http://{{/}}localhost:1823/_/meow.git/git-receive-pack
```

When parsed, the host is `{{` and the port is empty, so this passes all the checks. When it is passed through `formatString`, the `{{/}}` is removed and the request is made to `http://localhost:1823`.

# Putting it all together

Now that we can push as admin, we can add our user to the `access.conf` file. To do this, we can set the body of the webhook to our git request. Luckily for us, the webhook accepts data encoded in Base64, so we can easily replicate the git operation.

To do this, we can run the server locally and log the request bodies using `morgan-body`.

```typescript
const main = async () => {
const app = express();

app.use(bodyParser.json());
morganBody(app);
```

We'll use regular `git` to push the appropriate files. Then, all we need to do is send this same payload to the real server, by Base64-encoding it and setting the Content-Type of the request to `application/x-git-receive-pack-request`. Once the webhook is triggered, an admin request will push to the access config file and give us access.

# Flag
```
picoCTF{good_job_at_gitting_good}
```
