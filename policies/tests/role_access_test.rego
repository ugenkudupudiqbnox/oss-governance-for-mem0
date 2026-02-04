package mem0.authz

test_reader_can_read if {
  allow with input as {
    "action": "read",
    "roles": ["agent-reader"],
    "tenant": "t1",
    "resource_tenant": "t1"
  }
}

test_reader_cannot_write if {
  not allow with input as {
    "action": "write",
    "roles": ["agent-reader"],
    "tenant": "t1",
    "resource_tenant": "t1"
  }
}

test_writer_can_write if {
  allow with input as {
    "action": "write",
    "roles": ["agent-writer"],
    "tenant": "t1",
    "resource_tenant": "t1"
  }
}

