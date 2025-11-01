package com.biswas.project_management_backend.controller;

import com.biswas.project_management_backend.dto.CompanyDto;
import com.biswas.project_management_backend.service.CompanyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/company")
public class CompanyController {

    @Autowired
    CompanyService companyService;

    @GetMapping("/{companyId}")
    public ResponseEntity<CompanyDto> getCompanyById(@PathVariable Long companyId) {
        CompanyDto company = companyService.getCompanyById(companyId);
        return ResponseEntity.ok(company);
    }
}
