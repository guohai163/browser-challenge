package cn.gydev.challenge.service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * DB repository for fingerprint whitelist records.
 */
@Repository
public class RiskFingerprintWhitelistRepository {

    private final JdbcTemplate jdbcTemplate;

    public RiskFingerprintWhitelistRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void upsert(
            String browserFamily,
            int majorVersion,
            String ja3,
            String ja3RawNormalized,
            String ja3Md5Normalized,
            String ja4,
            String h2,
            String source,
            boolean requireJa3) {
        Long existingId = requireJa3
                ? findId(browserFamily, majorVersion, ja3Md5Normalized, ja4, h2)
                : findIdWithoutJa3(browserFamily, majorVersion, ja4, h2);
        if (existingId == null) {
            jdbcTemplate.update(
                    """
                    INSERT INTO risk_fingerprint_whitelist
                    (browser_family, major_version, ja3, ja3_raw_normalized, ja3_md5_normalized, ja4, h2, enabled, source, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    browserFamily,
                    majorVersion,
                    ja3,
                    ja3RawNormalized,
                    ja3Md5Normalized,
                    ja4,
                    h2,
                    source
            );
            return;
        }

        jdbcTemplate.update(
                """
                UPDATE risk_fingerprint_whitelist
                SET enabled = TRUE,
                    source = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                source,
                existingId
        );
    }

    public boolean isWhitelisted(String browserFamily, int majorVersion, String ja3Md5Normalized, String ja4, String h2) {
        Integer count = jdbcTemplate.queryForObject(
                """
                SELECT COUNT(1)
                FROM risk_fingerprint_whitelist
                WHERE enabled = TRUE
                  AND browser_family = ?
                  AND major_version = ?
                  AND ja3_md5_normalized = ?
                  AND ja4 = ?
                  AND h2 = ?
                """,
                Integer.class,
                browserFamily,
                majorVersion,
                ja3Md5Normalized,
                ja4,
                h2
        );
        return count != null && count > 0;
    }

    public boolean isWhitelistedWithoutJa3(String browserFamily, int majorVersion, String ja4, String h2) {
        Integer count = jdbcTemplate.queryForObject(
                """
                SELECT COUNT(1)
                FROM risk_fingerprint_whitelist
                WHERE enabled = TRUE
                  AND browser_family = ?
                  AND major_version = ?
                  AND ja4 = ?
                  AND h2 = ?
                """,
                Integer.class,
                browserFamily,
                majorVersion,
                ja4,
                h2
        );
        return count != null && count > 0;
    }

    public List<Record> listEnabled() {
        return jdbcTemplate.query(
                """
                SELECT id, browser_family, major_version, ja3, ja3_raw_normalized, ja3_md5_normalized, ja4, h2, source, created_at, updated_at
                FROM risk_fingerprint_whitelist
                WHERE enabled = TRUE
                ORDER BY browser_family, major_version, id
                """,
                this::mapRecord
        );
    }

    private Long findId(String browserFamily, int majorVersion, String ja3Md5Normalized, String ja4, String h2) {
        List<Long> ids = jdbcTemplate.query(
                """
                SELECT id
                FROM risk_fingerprint_whitelist
                WHERE browser_family = ?
                  AND major_version = ?
                  AND ja3_md5_normalized = ?
                  AND ja4 = ?
                  AND h2 = ?
                LIMIT 1
                """,
                (rs, rowNum) -> rs.getLong("id"),
                browserFamily,
                majorVersion,
                ja3Md5Normalized,
                ja4,
                h2
        );
        return ids.isEmpty() ? null : ids.getFirst();
    }

    public Long findIdWithoutJa3(String browserFamily, int majorVersion, String ja4, String h2) {
        List<Long> ids = jdbcTemplate.query(
                """
                SELECT id
                FROM risk_fingerprint_whitelist
                WHERE browser_family = ?
                  AND major_version = ?
                  AND ja4 = ?
                  AND h2 = ?
                LIMIT 1
                """,
                (rs, rowNum) -> rs.getLong("id"),
                browserFamily,
                majorVersion,
                ja4,
                h2
        );
        return ids.isEmpty() ? null : ids.getFirst();
    }

    private Record mapRecord(ResultSet rs, int rowNum) throws SQLException {
        return new Record(
                rs.getLong("id"),
                rs.getString("browser_family"),
                rs.getInt("major_version"),
                rs.getString("ja3"),
                rs.getString("ja3_raw_normalized"),
                rs.getString("ja3_md5_normalized"),
                rs.getString("ja4"),
                rs.getString("h2"),
                rs.getString("source"),
                String.valueOf(rs.getTimestamp("created_at")),
                String.valueOf(rs.getTimestamp("updated_at"))
        );
    }

    public record Record(
            long id,
            String browserFamily,
            int majorVersion,
            String ja3,
            String ja3RawNormalized,
            String ja3Md5Normalized,
            String ja4,
            String h2,
            String source,
            String createdAt,
            String updatedAt
    ) {
    }
}
