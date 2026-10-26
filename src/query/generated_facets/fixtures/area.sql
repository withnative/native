SELECT r.id AS "id",
       r.name AS "name",
       r.type AS "type",
       r.kind AS "kind",
       r.home_id AS "home_id",
       r.archived AS "archived",
       r.lifecycle AS "lifecycle",
       r.is_current AS "is_current",
       f0.value AS "area",
       f0.value AS "area__raw",
       CASE WHEN f0.record_id IS NULL OR f0.value IS NULL THEN 'missing' ELSE 'valid' END AS "area__status"
FROM records AS r
LEFT JOIN facet_values AS f0 ON f0.record_id = r.id AND f0.key = 'area'
WHERE r.type = 'WorkItem' AND r.kind = 'task' AND r.home_id = 'H'
