# https://github.com/cisagov/vulnrichment/blob/develop/2025/33xxx/CVE-2025-33028.json
$cve = $(Invoke-WebRequest -uri "https://raw.githubusercontent.com/cisagov/vulnrichment/refs/heads/develop/2025/33xxx/CVE-2025-33028.json" -Method Get -UseBasicParsing).content | convertfrom-json
$exploitation = $($($($cve.containers.adp | Where-Object {$_.title -eq "CISA ADP Vulnrichment"}).metrics.other | Where-Object {$_.type -eq "ssvc"}).content | Where-Object {$_.role -eq "CISA Coordinator"}).options.exploitation[0].trim()
$automatable = $($($($cve.containers.adp | Where-Object {$_.title -eq "CISA ADP Vulnrichment"}).metrics.other | Where-Object {$_.type -eq "ssvc"}).content | Where-Object {$_.role -eq "CISA Coordinator"}).options.automatable[1].trim()
$tech_impact = $($($($cve.containers.adp | Where-Object {$_.title -eq "CISA ADP Vulnrichment"}).metrics.other | Where-Object {$_.type -eq "ssvc"}).content | Where-Object {$_.role -eq "CISA Coordinator"}).options."technical impact"[2].trim()

$test = @()
#$test += "cve_id,exploitation,automatable,technicalimpact,mission,wellbeing"
#$test += "CVE-2025-33028,poc,yes,partial,support,Irreversible"
$test += "cve_id,exploitation,automatable,technicalimpact"
$test += "CVE-2025-33028,$exploitation,$automatable,$tech_impact"
$test = $test | ConvertFrom-Csv
$test.Exploitation -eq "poc"

# https://www.cisa.gov/ssvc-calculator
class TreeWrite
    {
        $output_val = $null;
        $offset = 0;

        # Main constructor. Just sets up the class
        TreeWrite() {
        }

        [void]print([string]$input_val) {
        #[string]print([string]$input_val) {
            $this.output_val = "$(" " * $this.offset)|_$input_val"
            $this.offset = $this.offset + $($input_val.length)
            #return $this.output_val
            write-host $this.output_val
        }
    }

function Get-SSVCDecision {
    param (
        [string]$Exploitation = "none",
        [string]$Automatable = "no",
        [string]$TechnicalImpact = "partial",
        [string]$Mission = "support",
        [string]$WellBeing = "material",
        [boolean]$logging = $false
    )

    $logger = [treewrite]::new()

    if (@("Active","poc","none") -notcontains $Exploitation) {if ($logging) {$logger.print("replaced exploitation")}; $exploitation = $none}
    if (@("yes","no") -notcontains $Automatable) {if ($logging) {$logger.print("replaced automatable")};$Automatable = "no"}
    if (@("partial","total") -notcontains $TechnicalImpact) {if ($logging) {$logger.print("replaced technical impact")};$TechnicalImpact = "partial"}
    if (@("minimal","support","essential") -notcontains $Mission) {if ($logging) {$logger.print("replaced mission")};$Mission = "support"}
    if (@("minimal","material","irreversible") -notcontains $WellBeing) {if ($logging) {$logger.print("replaced wellbeing")};$WellBeing = "material"}


    switch ($Exploitation) {
        "active" {if ($logging) {$logger.print($switch.current)};
            switch ($Automatable) {
                "yes" {if ($logging) {$logger.print($switch.current)};
                    switch ($TechnicalImpact) {
                        "Total" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; return "Act*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Act" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Act" }
                                    }
                                }
                                default { return "Mission:Act" }
                            }
                        }
                        "Partial" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Attend" }
                            }
                        }
                        default { return "TechnicalImpact:Attend" }
                    }
                }
                "no" {if ($logging) {$logger.print($switch.current)};
                    switch ($TechnicalImpact) {
                        "Total" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Act" }
                                    }
                                }
                                default { return "Mission:Act" }
                            }
                        }
                        "Partial" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Attend" }
                            }
                        }
                        default { return "TechnicalImpact:Attend" }
                    }
                }
                default { return "Automatable:Act" }
            }
        }
        "poc" {if ($logging) {$logger.print($switch.current)};
            switch ($Automatable) {
                "yes" {if ($logging) {$logger.print($switch.current)};
                    switch ($TechnicalImpact) {
                        "Total" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Act" }
                            }
                        }
                        "Partial" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Attend" }
                            }
                        }
                        default { return "TechnicalImpact:Act" }
                    }
                }
                "no" {if ($logging) {$logger.print($switch.current)};
                    switch ($TechnicalImpact) {
                        "Total" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Act" }
                            }
                        }
                        "Partial" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Act")}; return "Act" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Attend" }
                            }
                        }
                        default { return "TechnicalImpact:Act" }
                    }
                    }
                default { return "Automatable:Attend" }
            }
        }
        "none" {if ($logging) {$logger.print($switch.current)};
            switch ($Automatable) {
                "yes" {if ($logging) {$logger.print($switch.current)};
                    switch ($TechnicalImpact) {
                        "Total" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Track" }
                            }
                        }
                        "Partial" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Attend" }
                                    }
                                }
                                default { return "Mission:Track" }
                            }
                        }
                        default { return "TechnicalImpact:Track*" }
                    }
                }
                "no" {if ($logging) {$logger.print($switch.current)};
                    switch ($TechnicalImpact) {
                        "Total" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        default { return "WellBeing:Track*" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track*")}; return "Track*" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Track*" }
                                    }
                                }
                                default { return "Mission:Track*" }
                            }
                        }
                        "Partial" {if ($logging) {$logger.print($switch.current)};
                            switch ($mission) {
                                "Minimal" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Support" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Track" }
                                    }
                                }
                                "Essential" {if ($logging) {$logger.print($switch.current)};
                                    switch ($WellBeing) {
                                        "Minimal" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Track")}; return "Track" }
                                        "Material" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        "Irreversible" {if ($logging) {$logger.print($switch.current)}; if ($logging) {$logger.print("Attend")}; return "Attend" }
                                        default { return "WellBeing:Track*" }
                                    }
                                }
                                default { return "Mission:Track" }
                            }
                        }
                        default { return "TechnicalImpact:Track" }
                    }
                    }
                default { return "Automatable:Track" }
            }
        }
        default { return "Exploitation:Track" }
    }
}

Get-SSVCDecision -Exploitation "active" -Automatable "yes" -TechnicalImpact "Total" -Mission "Minimal" -WellBeing "Irreversible" -logging $true
Get-SSVCDecision -Exploitation "active" -Automatable "yes" -TechnicalImpact "Total" -Mission "Minimal" -WellBeing "other" -logging $true

###########################################################
# What is effectively a unit test                         #
# Just to test and see what happens for all eventualities #
###########################################################
$exploits = @("Active","poc","none")
$autos = @("yes","no")
$techs = @("partial","total")
$misses = @("minimal","support","essential")
$wells = @("minimal","material","irreversible")

foreach ($ex in $exploits)
    {
        foreach ($auto in $autos)
            {
                foreach ($tech in $techs)
                    {
                        foreach ($miss in $misses)
                            {
                                foreach ($well in $wells)
                                    {
                                        $empty = Get-SSVCDecision -Exploitation $ex -Automatable $auto -TechnicalImpact $tech -Mission $miss -WellBeing $well -logging $true
                                    }
                            }
                    }
            }
    }
###########################################################
# What is effectively a unit test                         #
# Just to test and see what happens for all eventualities #
###########################################################

Get-SSVCDecision -Exploitation $test.Exploitation -Automatable $test.Automatable -TechnicalImpact $test.TechnicalImpact -Mission $test.Mission -WellBeing $test.WellBeing -logging $true

$test | ForEach-Object {
    #$_ | Add-Member -MemberType NoteProperty -Name "SSVC_Decision" -Value (Get-SSVCDecision -Exploitation $_.Exploitation -Automatable $_.Automatable -TechnicalImpact $_.TechnicalImpact -Mission $_.Mission -WellBeing $_.WellBeing)
    Get-SSVCDecision -Exploitation $_.Exploitation -Automatable $_.Automatable -TechnicalImpact $_.TechnicalImpact -Mission $_.Mission -WellBeing $_.WellBeing
}

Get-SSVCDecision -Exploitation "poc" -logging $true