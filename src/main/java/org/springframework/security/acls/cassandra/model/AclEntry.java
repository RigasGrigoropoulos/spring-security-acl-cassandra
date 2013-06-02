package org.springframework.security.acls.cassandra.model;

public class AclEntry {

	// id pattern: objectIdentity_:_sid
	private String id;
	private String objectIdentity;
	private String sid;
	private boolean sidPrincipal;
	private int order;
	private int mask;
	private boolean granting;
	private boolean auditSuccess;
	private boolean auditFailure;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getObjectIdentity() {
		return objectIdentity;
	}

	public void setObjectIdentity(String objectIdentity) {
		this.objectIdentity = objectIdentity;
	}

	public boolean isSidPrincipal() {
		return sidPrincipal;
	}

	public void setSidPrincipal(boolean sidPrincipal) {
		this.sidPrincipal = sidPrincipal;
	}

	public String getSid() {
		return sid;
	}

	public void setSid(String sid) {
		this.sid = sid;
	}

	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public int getMask() {
		return mask;
	}

	public void setMask(int mask) {
		this.mask = mask;
	}

	public boolean isGranting() {
		return granting;
	}

	public void setGranting(boolean granting) {
		this.granting = granting;
	}

	public boolean isAuditSuccess() {
		return auditSuccess;
	}

	public void setAuditSuccess(boolean auditSuccess) {
		this.auditSuccess = auditSuccess;
	}

	public boolean isAuditFailure() {
		return auditFailure;
	}

	public void setAuditFailure(boolean auditFailure) {
		this.auditFailure = auditFailure;
	}

}
