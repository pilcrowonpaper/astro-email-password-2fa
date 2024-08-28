/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />
declare namespace App {
	interface Locals {
		user: import("./lib/server/user").User | null;
		session: import("./lib/server/session").Session | null;
	}
}
