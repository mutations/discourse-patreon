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

## About

This is a work in progress! Feel free to use and ask questions here, or on [Meta](https://meta.discourse.org/t/discourse-patreon-login/44366?u=falco).

## TODO

- Job to sync existing Creators with the corresponding Patreon account
