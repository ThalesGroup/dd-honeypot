## Honeypot data usage examples

Here you can find documentation and examples for creating Data Lake tables, to make the data collected using dd-honeypot accessible for analysis. You can use the [logging-readme.md](logging-readme.md) to learn how to send data to S3 using fluent-bit.

### Create a Data Lake table from the data in S3
You can use AWS Glue to create a Data Lake table from the data in S3. You can also use the following SQL command in Athena to create the table:
```sql
CREATE EXTERNAL TABLE `dd_honeypot`(
  `region` string , 
  `time` string , 
  `session-id` string , 
  `type` string , 
  `name` string , 
  `login` struct<client_ip:string,username:string> , 
  `command` string , 
  `method` string , 
  `http-request` struct<host:string,port:smallint,args:map<string,string>,method:string,headers:map<string,string>,resource_type:string,body:string,path:string> , 
  `query` string )
COMMENT 'Honeypot logs collected using dd-honeypot and fluent-bit'
PARTITIONED BY ( 
  `day` string, 
  `hour` tinyint)
ROW FORMAT SERDE 
  'org.openx.data.jsonserde.JsonSerDe' 
WITH SERDEPROPERTIES ( 
  'ignore.malformed.json'='true') 
LOCATION
  's3://your-bucket-name/logs'
```
Here is an example of how to run a query on the table:
```sql
ALTER TABLE dd_honeypot ADD 
PARTITION (day='2025-11-01', hour=10) -- add partition for November 1, 2025, hour 10;

SELECT * 
  FROM dd_honeypot 
 WHERE day='2025-11-01' 
       AND hour=10 
 LIMIT 10;
```

Example for loading data for mysql honeypots protocol for 30d backs:
```sql
SELECT MIN(time) AS time, 
       ARRAY_AGG(query) AS queries
FROM dd_honeypot
WHERE type = 'mysql'
      AND query IS NOT NULL
      AND DATE(day) BETWEEN DATE_ADD('day', -30, CURRENT_DATE) AND DATE_ADD('day', -1, CURRENT_DATE)
GROUP BY session_id
ORDER BY time
```
This data can be used to analyze the commands sent to the honeypot, and to identify patterns in the attacks. Data can also be sent to LLMs for further analysis. If data is too large, consider changing the filtering and aggregation criteria to reduce the amount of data sent to the LLM. The data can also be chunked before it is sent to the LLM.