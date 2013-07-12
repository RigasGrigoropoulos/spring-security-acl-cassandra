/* Copyright 2013 Rigas Grigoropoulos
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.test;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.acls.cassandra.repository.CassandraAclRepositoryImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.test.service.Report;
import org.springframework.security.acls.test.service.ReportService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.ExpectedException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Host;
import com.datastax.driver.core.Metadata;
import com.datastax.driver.core.Session;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:/service-context.xml", "classpath:/context.xml" })
public class ReportServiceTest {
	
	private static final String KEYSPACE = "SpringSecurityAclCassandra";
	private static final String sid1 = "sid1@system";
	
	@Autowired
	private CassandraAclRepositoryImpl service;

	@Autowired
	private Cluster cluster;
	
	private Session session;
	
	@Autowired
	private ReportService testService;
	
	@Autowired
	private MutableAclService aclService;

	@Before
	public void setUp() throws Exception {
		Metadata metadata = cluster.getMetadata();
		System.out.printf("Connected to cluster: %s\n", metadata.getClusterName());
		for (Host host : metadata.getAllHosts()) {
			System.out.printf("Datacenter: %s; Host: %s; Rack: %s\n", host.getDatacenter(), host.getAddress(), host.getRack());
		}
		
		session = cluster.connect();
		service.createKeyspace();
		service.createAoisTable();
		service.createAclsTable();
		service.createChilrenTable();

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(sid1, "password", Arrays.asList(new SimpleGrantedAuthority[] { new SimpleGrantedAuthority(
						"ROLE_USER") })));
	}

	@After
	public void tearDown() throws Exception {
		testService.clearReports();
		session.execute("DROP KEYSPACE " + KEYSPACE);
	}

	@Test
	@ExpectedException(AccessDeniedException.class)
	public void testGetReportAccessDenied() {		
		Report report = testService.addReport(createReport());		
		testService.getReport(report.getId());
	}
	
	@Test
	@ExpectedException(AccessDeniedException.class)
	public void testDeleteReportAccessDenied() {		
		Report report = testService.addReport(createReport());		
		testService.deleteReport(report);
	}
	
	@Test
	@ExpectedException(AccessDeniedException.class)
	public void testModifyReportAccessDenied() {		
		Report report = testService.addReport(createReport());		
		testService.modifyReport(report);
	}
	
	@Test
	public void testGetReportSuccess() {		
		Report report = testService.addReport(createReport());
		createReadWriteDeleteAcl(sid1, report);
		report = testService.getReport(report.getId());
		assertNotNull(report);
	}
	
	@Test
	public void testDeleteReportSuccess() {		
		Report report = testService.addReport(createReport());
		createReadWriteDeleteAcl(sid1, report);
		testService.deleteReport(report);
		report = testService.getReport(report.getId());
		assertNull(report);
	}
	
	@Test
	public void testModifyReportSuccess() {		
		Report report = testService.addReport(createReport());
		createReadWriteDeleteAcl(sid1, report);
		report.setName("Modified");
		testService.modifyReport(report);
		report = testService.getReport(report.getId());
		assertNotNull(report);
		assertEquals("Modified", report.getName());
	}
	
	private Report createReport() {
		Report report = new Report();
		report.setName("Test Report");
		report.setContent("Report Content");
		return report;
	}
	
	private void createReadWriteDeleteAcl(String sid, Report report) {
		MutableAcl acl = aclService.createAcl(new ObjectIdentityImpl(report));
		acl.insertAce(0, BasePermission.READ, new PrincipalSid(sid), true);
		acl.insertAce(1, BasePermission.WRITE, new PrincipalSid(sid), true);
		acl.insertAce(2, BasePermission.DELETE, new PrincipalSid(sid), true);
		aclService.updateAcl(acl);
	}

}
