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
package org.springframework.security.acls.test.service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

public class ReportServiceImpl implements ReportService {
	
	Map<String, Report> reports = new HashMap<String, Report>();

	@PostAuthorize("hasPermission(returnObject, 'READ')")
	public Report getReport(String id) {
		return reports.get(id);
	}

	public Report addReport(Report report) {
		report.setId(UUID.randomUUID().toString());
		reports.put(report.getId(), report);
		return report;
	}

	@PreAuthorize("hasPermission(#report, 'WRITE')")
	public Report modifyReport(Report report) {
		reports.put(report.getId(), report);
		return report;
	}

	@PreAuthorize("hasPermission(#report, 'DELETE')")
	public void deleteReport(Report report) {
		reports.remove(report.getId());
	}

	public void clearReports() {
		reports.clear();
	}

}
