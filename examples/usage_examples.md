# Icinga2 MCP Usage Examples

This document provides practical examples of using the Icinga2 MCP server with Claude or other AI assistants.

## Setup

After installing and configuring the MCP server in your Claude Desktop or other MCP client, you can use natural language to interact with your Icinga2 monitoring system.

## Example Queries

### Checking Host Status

**Simple query:**
```
"Show me all hosts"
```

**Filtered query:**
```
"Show me all web servers that are down"
```

**Detailed query:**
```
"Give me detailed information about the database servers"
```

### Checking Service Status

**Simple query:**
```
"Show me all services"
```

**Problem-focused query:**
```
"Show me all services that are in a warning or critical state"
```

**Service-specific query:**
```
"Show me all HTTP services across all hosts"
```

**Host-specific query:**
```
"Show me all services on web01.example.com"
```

### Getting Detailed Information

**Specific host:**
```
"Get detailed information about web01.example.com"
```

**Specific service:**
```
"Get details about the MySQL service on db-master.example.com"
```

### Managing Downtimes

**Schedule downtime for a host:**
```
"Schedule 2 hour downtime for web01.example.com starting now for planned maintenance"
```

**Schedule downtime for a service:**
```
"Schedule downtime for the MySQL service on db-master.example.com starting in 30 minutes for 1 hour"
```

**Schedule downtime for host and all services:**
```
"Schedule 4 hour downtime for app01.example.com and all its services starting now for system upgrade"
```

### Acknowledging Problems

**Acknowledge host problem:**
```
"Acknowledge the problem on web01.example.com - investigating high load issue"
```

**Acknowledge service problem:**
```
"Acknowledge the critical state of MySQL on db-master.example.com - working on fix"
```

**Sticky acknowledgment:**
```
"Acknowledge the disk space warning on storage01 with sticky acknowledgment - will resolve after hours"
```

## Complex Scenarios

### Maintenance Workflow

**Scenario:** You need to perform maintenance on a database server.

```
User: "I need to perform maintenance on db-master.example.com tonight"

AI: "I'll help you prepare for that. Let me first check the current status."
    [Calls get_host_details for db-master.example.com]

User: "Please schedule a 2 hour downtime starting at 10 PM tonight for all services"

AI: [Schedules downtime with appropriate start time and duration]
```

### Problem Investigation

**Scenario:** Investigating service issues.

```
User: "Are there any critical services right now?"

AI: [Calls list_services with state=critical]
    "I found 3 critical services:
    - MySQL on db-master.example.com
    - Disk / on storage01.example.com
    - HTTP on web02.example.com"

User: "Show me details about the MySQL issue"

AI: [Calls get_service_details]
    "The MySQL service is critical with the message: 'Connection refused on port 3306'..."

User: "I'm working on it, acknowledge this problem"

AI: [Calls acknowledge_problem with appropriate details]
```

### Capacity Planning

**Scenario:** Reviewing infrastructure status.

```
User: "Give me a summary of all my infrastructure"

AI: [Calls list_hosts with summary detail level]
    [Calls list_services with state=problem]
    "Here's your infrastructure overview:
    - Total hosts: 45 (42 UP, 3 DOWN)
    - Services with problems: 7
    ..."

User: "Show me which hosts are down"

AI: [Calls list_hosts with state=down and normal detail level]
```

## Detail Level Guidelines

The MCP server supports three detail levels. The AI will typically choose automatically, but you can request:

- **Summary**: For quick overviews and lists (less context usage)
- **Normal**: For standard operational information (default)
- **Detailed**: For deep investigation and troubleshooting

Example:
```
"Show me a summary of all hosts" → Uses summary detail level
"What's wrong with web01?" → Uses detailed detail level
"List all services" → Uses normal detail level
```

## Best Practices

1. **Be specific about timeframes** when scheduling downtimes
2. **Include meaningful comments** when acknowledging problems
3. **Use filters** to narrow down large result sets
4. **Request appropriate detail levels** to optimize performance
5. **Combine queries** for comprehensive investigation workflows

## Tips

- The AI can handle natural language, so don't worry about exact syntax
- You can ask follow-up questions to refine results
- The AI will suggest next steps based on the current state
- Use specific host/service names when you know them for faster results
