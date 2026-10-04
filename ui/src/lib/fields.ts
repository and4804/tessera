import type { QueryField } from "@/api/types";

/**
 * Fallback field whitelist for the query bar. It mirrors the FROZEN lake schema in
 * IMPLEMENTATION_GUIDE §7.9 (names/types only, no data). When the API serves
 * GET /events/fields, that list replaces this one.
 */
export const LAKE_FIELDS: QueryField[] = [
  { name: "src_ip", type: "ip", description: "Source address (CIDR ok)" },
  { name: "dst_ip", type: "ip", description: "Destination address (CIDR ok)" },
  { name: "src_port", type: "int", description: "Source port" },
  { name: "dst_port", type: "int", description: "Destination port" },
  { name: "proto_name", type: "string", description: "Protocol name (tcp, udp, icmp…)" },
  { name: "proto_num", type: "int", description: "IANA protocol number" },
  { name: "action", type: "enum", enum: ["allowed", "denied"], description: "Normalized action (alias of action_id)" },
  { name: "action_id", type: "int", description: "OCSF action_id" },
  { name: "activity_id", type: "int", description: "OCSF activity_id" },
  { name: "severity_id", type: "int", description: "OCSF severity_id (0–6)" },
  { name: "class_uid", type: "int", description: "OCSF class (4001 network, 4002 http, …)" },
  { name: "status", type: "enum", enum: ["parsed", "partial", "unparsed"], description: "Terminal parse state" },
  { name: "source_id", type: "string", description: "Source pack id" },
  { name: "bytes_in", type: "int", description: "Bytes received" },
  { name: "bytes_out", type: "int", description: "Bytes sent" },
  { name: "packets_in", type: "int", description: "Packets received" },
  { name: "packets_out", type: "int", description: "Packets sent" },
  { name: "duration_ms", type: "int", description: "Connection duration (ms)" },
  { name: "user_name", type: "string", description: "Account / user" },
  { name: "url", type: "string", description: "Request URL" },
  { name: "http_method", type: "string", description: "HTTP method" },
  { name: "http_status", type: "int", description: "HTTP status code" },
  { name: "dns_query", type: "string", description: "DNS query name" },
  { name: "signature", type: "string", description: "IDS/UTM signature or title" },
  { name: "device_host", type: "string", description: "Reporting device hostname" },
  { name: "coverage", type: "float", description: "Mapped / extracted field ratio (0–1)" },
  { name: "event_id", type: "string", description: "<raw_id>:<n>" },
  { name: "raw_ref", type: "string", description: "segment/block/idx" }
];
