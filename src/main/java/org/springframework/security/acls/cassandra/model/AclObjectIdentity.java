package org.springframework.security.acls.cassandra.model;

public class AclObjectIdentity {

	// id pattern: objectClass_:_objectId
	private String id;
	private String objectClass;
	private String parentObjectId;
	private String ownerId;
	private boolean ownerPrincipal;
	private boolean entriesInheriting;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getObjectClass() {
		return objectClass;
	}

	public boolean isOwnerPrincipal() {
		return ownerPrincipal;
	}

	public void setOwnerPrincipal(boolean ownerPrincipal) {
		this.ownerPrincipal = ownerPrincipal;
	}

	public void setObjectClass(String objectClass) {
		this.objectClass = objectClass;
	}

	public String getParentObjectId() {
		return parentObjectId;
	}

	public void setParentObjectId(String parentObjectId) {
		this.parentObjectId = parentObjectId;
	}

	public String getOwnerId() {
		return ownerId;
	}

	public void setOwnerId(String ownerId) {
		this.ownerId = ownerId;
	}

	public boolean isEntriesInheriting() {
		return entriesInheriting;
	}

	public void setEntriesInheriting(boolean entriesInheriting) {
		this.entriesInheriting = entriesInheriting;
	}

}
