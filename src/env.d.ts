/// <reference types="astro/client" />
declare namespace App {
	interface Locals {
		user: import("./lib/user").User | null;
		session: import("./lib/session").Session | null;
	}
}
