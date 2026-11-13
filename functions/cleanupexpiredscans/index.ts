
import { Pool } from "pg";
import { attachDatabasePool } from "@neon/functions";
import { parseTriggerInvocation } from "@neon/functions/triggers";

let pool: Pool | undefined;

const RETENTION_DAYS = 21;

function getPool(): Pool {
    if (!pool) {
        const databaseUrl = process.env.DATABASE_URL;

        if (!databaseUrl) {
            throw new Error("DATABASE_URL is not configured");
        }

        pool = new Pool({
            connectionString: databaseUrl,
            max: 5,
        });

        attachDatabasePool(pool);
    }

    return pool;
}

export default {
    async fetch(request: Request): Promise<Response> {
        if (request.method !== "POST") {
            return Response.json(
                { error: "Method not allowed" },
                { status: 405 }
            );
        }

        const parsed = await parseTriggerInvocation(request);

        if (!parsed.ok) {
            const status = parsed.error === "invalid_body" ? 400 : 401;

            return Response.json(
                { error: parsed.error },
                { status }
            );
        }

        try {
            const db = getPool();

            const result = await db.query(
                `DELETE FROM scan_history
                 WHERE created_at < NOW() - INTERVAL '21 days'`
            );

            return Response.json({
                success: true,
                retention_days: RETENTION_DAYS,
                deleted_count: result.rowCount ?? 0,
                scheduled_at: parsed.invocation.data.scheduledAt,
            });
        } catch (error) {
            console.error(
                "Scan cleanup failed:",
                error instanceof Error ? error.message : "Unknown error"
            );

            return Response.json(
                { error: "Scan cleanup failed" },
                { status: 500 }
            );
        }
    },
};
