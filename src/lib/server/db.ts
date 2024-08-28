import sqlite3 from "better-sqlite3";
import { SyncDatabase } from "@pilcrowjs/db-query";

import type { SyncAdapter } from "@pilcrowjs/db-query";

const sqlite = sqlite3("sqlite.db");

const adapter: SyncAdapter<sqlite3.RunResult> = {
	query: (statement: string, params: unknown[]): unknown[][] => {
		const result = sqlite
			.prepare(statement)
			.raw()
			.all(...params);
		return result as unknown[][];
	},
	execute: (statement: string, params: unknown[]): sqlite3.RunResult => {
		const result = sqlite.prepare(statement).run(...params);
		return result;
	}
};

class Database extends SyncDatabase<sqlite3.RunResult> {
	public inTransaction(): boolean {
		return sqlite.inTransaction;
	}
}

export const db = new Database(adapter);
