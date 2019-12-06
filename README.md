# Discourse Patreon for Creators

Enables Login for Patreon Creators, Patrons are not allowed to login when this plugin is installed.

<img src="public/images/patreon-wordmark-navy.png?raw=true" width="292" height="104">

If the Creator has an `Adult content` campaign, then the user is added to the group configured in the plugin settings.  If there is no `Adult content` campaign, then the user is removed from the configured group.

## Installation

Proceed with a normal [installation of a plugin](https://meta.discourse.org/t/install-a-plugin/19157?u=falco).


## After Installation

You need to fill the following fields on Settings -> Plugins:

- Client ID
- Client Secret
- Creator's Access Token
- Creator's Refesh Token
- Creator NSFW Group

To get those values you must have a [Creator account first](https://www.patreon.com/become-a-patreon-creator).

Then go to [Clients & API Keys](https://www.patreon.com/platform/documentation/clients) and fill the necessary info.

> The Redirect URIs must be `http://<DISCOURSE BASE URL>/auth/patreon/callback`, like https://meta.discourse.org/auth/patreon/callback for example.

Then you use the generated tokens to configure the plugin.

## Social Login

This plugin will also enable a Social Login with Patreon, making it easier for your patron to sign up on Discourse.

<img src="https://discourse-meta.s3-us-west-1.amazonaws.com/original/3X/d/6/d6fc81667227c41d1a59f374fa10dbc31c32bdf0.png" width="690" height="329">


## Local development

Use the below steps to set up your local dev environment:

1. Clone git@github.com:discourse/discourse_docker.git
1. cd into the new repo `cd discourse_docker`
1. Copy the `example_app.yml` from this gist to `containers/app.yml`.
1. Edit the different TODO lines and fill in the data.
1. Edit `app.yml`, lines `79` and `82`. Specify the path to the `shared/standalone` folder.
1. Edit `app.yml`, line `94` and specify the branch of the plugin you want to run.  Currently, it is set to `master` branch. Line `95` is an example of how to specify the branch.
1. Install the `lvh.me` SSL cert and key into the `shared/standalone/ssl/ssl.crt` and `shared/standalone/ssl/ssl.key`. Refer to `Terminal Development TLS Certificates` in 1Password.
1. Run the following: `./launcher rebuild app`
1. wait
1. Once all done, you can browse to https://lvh.me:8443/

### Update plugin

1. Change the `app.yml` and point it to your branch.
1. Rebuild the app `./launcher rebuild app`
1. Now your Discourse is pointed to your branch of the plugin.
1. To deploy plugin changes, you can push them up to `origin` and then browse to `https://lvh.me:8443/admin/upgrade`.  You can then upgrade without doing a full `launger rebuild app`.

## Other resources

https://meta.discourse.org/t/advanced-setup-only-allowing-ssl-https-for-your-discourse-docker-setup/13847
