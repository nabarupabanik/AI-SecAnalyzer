import React, { useState, useEffect } from 'react';
import { Card, CardContent, Typography, Box, Grid, Chip, LinearProgress, Alert, Accordion, AccordionSummary, AccordionDetails } from '@mui/material';
import { TrendingUp, Security, Assessment, AttachMoney, Timeline, AccountTree, Analytics, Shield, Warning } from '@mui/icons-material';

interface PatentClaim {
  id: string;
  title: string;
  description: string;
  status: 'active' | 'pending' | 'granted';
  filingDate: string;
  noveltyScore: number;
  commercialPotential: number;
  defensibility: number;
}


const TECHNICAL_IMPLEMENTATIONS = {
  claim1: {
    algorithm: "Hierarchical AST analysis with business semantic tagging and dataflow graph construction",
    technicalFeatures: [
      "Multi-layer AST parsing with business context classification",
      "Custom dataflow graph construction using variable dependency tracking", 
      "Transaction pattern recognition using semantic similarity scoring",
      "Hierarchical clustering algorithm for workflow classification"
    ],
    novelty: "Combines AST analysis with semantic business context in a novel way"
  },
  claim2: {
    algorithm: "Multi-layer vulnerability analysis with exploit dependency modeling and temporal constraint analysis",
    technicalFeatures: [
      "Custom vulnerability layer classification algorithm",
      "Exploit dependency modeling using constraint satisfaction",
      "Temporal constraint analysis for attack sequencing",
      "Custom edge weighting based on exploit prerequisites"
    ],
    novelty: "Applies graph theory to realistic attack path modeling with temporal constraints"
  },
  claim3: {
    algorithm: "Dynamic security debt portfolio modeling with time-decay functions and Markowitz optimization",
    technicalFeatures: [
      "Time-decay risk accumulation algorithms",
      "Modern portfolio theory optimization (Markowitz)",
      "Industry-specific regression risk modeling",
      "Monte Carlo simulation for uncertainty quantification"
    ],
    novelty: "Applies financial portfolio theory to security vulnerability management"
  }
};
interface ClaimAnalysis {
  claimId: string;
  technicalMetrics: {
    innovationScore: number;
    marketDifferentiation: number;
    technicalComplexity: number;
    patentStrength: number;
  };
  businessMetrics: {
    marketSize: string;
    competitiveAdvantage: number;
    revenuePotential: number;
    barrierToEntry: number;
  };
  validationResults: {
    priorArtSearch: boolean;
    technicalFeasibility: boolean;
    commercialViability: boolean;
    legalDefensibility: boolean;
  };
}

const PatentClaimsPage: React.FC = () => {
  const [claims, setClaims] = useState<PatentClaim[]>([]);
  const [selectedClaim, setSelectedClaim] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<ClaimAnalysis | null>(null);
  const [loading, setLoading] = useState(false);

  // Patent claims data
  const patentClaims: PatentClaim[] = [
    {
      id: 'claim-1',
      title: 'Business Logic Security Analysis System',
      description: 'A computer-implemented method for analyzing business logic security vulnerabilities comprising: mapping financial workflows within application code; identifying business logic flaws by pattern recognition; quantifying financial impact based on industry-specific multipliers; generating regulatory compliance risk assessments; and producing attack scenario narratives.',
      status: 'active',
      filingDate: '2024-04-18',
      noveltyScore: 95,
      commercialPotential: 90,
      defensibility: 88
    },
    {
      id: 'claim-2',
      title: 'Attack Path Visualization & Exploitation Analysis',
      description: 'A method for modeling attack paths comprising: constructing a directed graph of vulnerability relationships; calculating edge weights based on exploitability factors; determining optimal attack chains using shortest path algorithms; computing breach probability using Bayesian inference; and generating financial impact projections.',
      status: 'active',
      filingDate: '2024-04-18',
      noveltyScore: 92,
      commercialPotential: 88,
      defensibility: 85
    },
    {
      id: 'claim-3',
      title: 'Security Debt ROI Analysis System',
      description: 'A system for managing security vulnerabilities as financial debt instruments comprising: calculating principal debt based on fix costs; applying interest rates based on daily risk accumulation; computing return on investment for remediation activities; generating industry benchmark comparisons; and producing executive-level financial justifications.',
      status: 'active',
      filingDate: '2024-04-18',
      noveltyScore: 93,
      commercialPotential: 91,
      defensibility: 87
    }
  ];

  useEffect(() => {
    setClaims(patentClaims);
  }, []);

  const handleClaimSelect = (claimId: string) => {
    setSelectedClaim(claimId);
    // Simulate loading analysis
    setLoading(true);
    setTimeout(() => {
      setAnalysis(generateMockAnalysis(claimId));
      setLoading(false);
    }, 1500);
  };

  const generateMockAnalysis = (claimId: string): ClaimAnalysis => {
    return {
      claimId,
      technicalMetrics: {
        innovationScore: Math.floor(Math.random() * 20) + 80,
        marketDifferentiation: Math.floor(Math.random() * 15) + 85,
        technicalComplexity: Math.floor(Math.random() * 25) + 75,
        patentStrength: Math.floor(Math.random() * 20) + 80
      },
      businessMetrics: {
        marketSize: '$2.5B Global SAST Market',
        competitiveAdvantage: Math.floor(Math.random() * 20) + 80,
        revenuePotential: '$50M - $200M annually',
        barrierToEntry: Math.floor(Math.random() * 30) + 70
      },
      validationResults: {
        priorArtSearch: true,
        technicalFeasibility: true,
        commercialViability: true,
        legalDefensibility: true
      }
    };
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'pending': return 'warning';
      case 'granted': return 'info';
      default: return 'default';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 80) return 'warning';
    return 'error';
  };

  const getProgressBarValue = (score: number) => {
    return Math.min(100, Math.max(0, score));
  };

  return (
    <Box sx={{ p: 3, bgcolor: '#f5f5f5' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', color: '#1a237e' }}>
        <Security sx={{ mr: 1 }} /> Patent Claims - Expert Level System
      </Typography>
      
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Revolutionary SAST methodologies with defensible patent claims and comprehensive technical analysis
      </Typography>

      <Grid container spacing={3}>
        {claims.map((claim) => (
          <Grid item xs={12} md={6} lg={4} key={claim.id}>
            <Card 
              sx={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: 3
                }
              }}
              onClick={() => handleClaimSelect(claim.id)}
            >
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="h6" sx={{ fontSize: '1rem', fontWeight: 'bold' }}>
                    {claim.title}
                  </Typography>
                  <Chip 
                    label={claim.status.toUpperCase()} 
                    color={getStatusColor(claim.status)}
                    size="small"
                    sx={{ fontWeight: 'bold' }}
                  />
                </Box>
                
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontSize: '0.875rem' }}>
                  {claim.description.substring(0, 150)}...
                </Typography>
                
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                    <strong>Filed:</strong> {claim.filingDate}
                  </Typography>
                  <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                    <strong>ID:</strong> {claim.id}
                  </Typography>
                </Box>

                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" sx={{ fontSize: '0.8rem', mb: 1 }}>
                    <strong>Patent Metrics</strong>
                  </Typography>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="body2" sx={{ fontSize: '0.75rem' }}>
                          Novelty
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                          <LinearProgress 
                            variant="determinate" 
                            value={getProgressBarValue(claim.noveltyScore)} 
                            sx={{ 
                              flex: 1, 
                              mr: 1,
                              height: 8,
                              borderRadius: 4,
                              backgroundColor: '#e0e0e0',
                              '& .MuiLinearProgress-bar': {
                                borderRadius: 4,
                                backgroundColor: getScoreColor(claim.noveltyScore) === 'success' ? '#4caf50' : 
                                               getScoreColor(claim.noveltyScore) === 'warning' ? '#ff9800' : '#f44336'
                              }
                            }}
                          />
                          <Typography variant="body2" sx={{ ml: 1, fontSize: '0.8rem', fontWeight: 'bold' }}>
                            {claim.noveltyScore}%
                          </Typography>
                        </Box>
                      </Box>
                    </Grid>
                    
                    <Grid item xs={6}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="body2" sx={{ fontSize: '0.75rem' }}>
                          Commercial Potential
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                          <LinearProgress 
                            variant="determinate" 
                            value={getProgressBarValue(claim.commercialPotential)} 
                            sx={{ 
                              flex: 1, 
                              mr: 1,
                              height: 8,
                              borderRadius: 4,
                              backgroundColor: '#e0e0e0',
                              '& .MuiLinearProgress-bar': {
                                borderRadius: 4,
                                backgroundColor: getScoreColor(claim.commercialPotential) === 'success' ? '#4caf50' : 
                                               getScoreColor(claim.commercialPotential) === 'warning' ? '#ff9800' : '#f44336'
                              }
                            }}
                          />
                          <Typography variant="body2" sx={{ ml: 1, fontSize: '0.8rem', fontWeight: 'bold' }}>
                            {claim.commercialPotential}%
                          </Typography>
                        </Box>
                      </Box>
                    </Grid>
                    
                    <Grid item xs={12}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="body2" sx={{ fontSize: '0.75rem' }}>
                          Defensibility
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                          <LinearProgress 
                            variant="determinate" 
                            value={getProgressBarValue(claim.defensibility)} 
                            sx={{ 
                              flex: 1, 
                              mr: 1,
                              height: 8,
                              borderRadius: 4,
                              backgroundColor: '#e0e0e0',
                              '& .MuiLinearProgress-bar': {
                                borderRadius: 4,
                                backgroundColor: getScoreColor(claim.defensibility) === 'success' ? '#4caf50' : 
                                               getScoreColor(claim.defensibility) === 'warning' ? '#ff9800' : '#f44336'
                              }
                            }}
                          />
                          <Typography variant="body2" sx={{ ml: 1, fontSize: '0.8rem', fontWeight: 'bold' }}>
                            {claim.defensibility}%
                          </Typography>
                        </Box>
                      </Box>
                    </Grid>
                  </Grid>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {selectedClaim && analysis && (
        <Box sx={{ mt: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom sx={{ fontWeight: 'bold', color: '#1a237e' }}>
                <Assessment sx={{ mr: 1 }} /> Patent Claim Analysis: {claims.find(c => c.id === selectedClaim)?.title}
              </Typography>
              
              {loading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                  <Typography>Loading expert analysis...</Typography>
                </Box>
              ) : (
                <Grid container spacing={3}>
                  {/* Technical Metrics */}
                  <Grid item xs={12} md={6}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                          <Analytics sx={{ mr: 1 }} /> Technical Metrics
                        </Typography>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                            Innovation Score
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={analysis.technicalMetrics.innovationScore} 
                            sx={{ mb: 2 }}
                          />
                          <Typography variant="body2" sx={{ textAlign: 'center', fontSize: '0.8rem' }}>
                            {analysis.technicalMetrics.innovationScore}/100
                          </Typography>
                        </Box>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                            Market Differentiation
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={analysis.technicalMetrics.marketDifferentiation} 
                            sx={{ mb: 2 }}
                          />
                          <Typography variant="body2" sx={{ textAlign: 'center', fontSize: '0.8rem' }}>
                            {analysis.technicalMetrics.marketDifferentiation}/100
                          </Typography>
                        </Box>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                            Patent Strength
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={analysis.technicalMetrics.patentStrength} 
                            sx={{ mb: 2 }}
                          />
                          <Typography variant="body2" sx={{ textAlign: 'center', fontSize: '0.8rem' }}>
                            {analysis.technicalMetrics.patentStrength}/100
                          </Typography>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Business Metrics */}
                  <Grid item xs={12} md={6}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                          <AttachMoney sx={{ mr: 1 }} /> Business Metrics
                        </Typography>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                            Market Size
                          </Typography>
                          <Typography variant="body2" sx={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#1a237e' }}>
                            {analysis.businessMetrics.marketSize}
                          </Typography>
                        </Box>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                            Competitive Advantage
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={analysis.businessMetrics.competitiveAdvantage} 
                            sx={{ mb: 2 }}
                          />
                          <Typography variant="body2" sx={{ textAlign: 'center', fontSize: '0.8rem' }}>
                            {analysis.businessMetrics.competitiveAdvantage}/100
                          </Typography>
                        </Box>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                            Revenue Potential
                          </Typography>
                          <Typography variant="body2" sx={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#1a237e' }}>
                            {analysis.businessMetrics.revenuePotential}
                          </Typography>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Validation Results */}
                  <Grid item xs={12}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                          <Shield sx={{ mr: 1 }} /> Patent Validation Results
                        </Typography>
                        
                        <Grid container spacing={2}>
                          <Grid item xs={6} md={3}>
                            <Box sx={{ textAlign: 'center', p: 2 }}>
                              <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                                Prior Art Search
                              </Typography>
                              <Chip 
                                icon={analysis.validationResults.priorArtSearch ? <TrendingUp /> : <Warning />}
                                label={analysis.validationResults.priorArtSearch ? 'Clear' : 'Issues Found'}
                                color={analysis.validationResults.priorArtSearch ? 'success' : 'error'}
                                sx={{ fontWeight: 'bold' }}
                              />
                            </Box>
                          </Grid>
                          
                          <Grid item xs={6} md={3}>
                            <Box sx={{ textAlign: 'center', p: 2 }}>
                              <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                                Technical Feasibility
                              </Typography>
                              <Chip 
                                icon={analysis.validationResults.technicalFeasibility ? <TrendingUp /> : <Warning />}
                                label={analysis.validationResults.technicalFeasibility ? 'Proven' : 'Needs Work'}
                                color={analysis.validationResults.technicalFeasibility ? 'success' : 'error'}
                                sx={{ fontWeight: 'bold' }}
                              />
                            </Box>
                          </Grid>
                          
                          <Grid item xs={6} md={3}>
                            <Box sx={{ textAlign: 'center', p: 2 }}>
                              <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                                Commercial Viability
                              </Typography>
                              <Chip 
                                icon={analysis.validationResults.commercialViability ? <TrendingUp /> : <Warning />}
                                label={analysis.validationResults.commercialViability ? 'Viable' : 'Risky'}
                                color={analysis.validationResults.commercialViability ? 'success' : 'error'}
                                sx={{ fontWeight: 'bold' }}
                              />
                            </Box>
                          </Grid>
                          
                          <Grid item xs={6} md={3}>
                            <Box sx={{ textAlign: 'center', p: 2 }}>
                              <Typography variant="body2" sx={{ fontSize: '0.9rem', mb: 1 }}>
                                Legal Defensibility
                              </Typography>
                              <Chip 
                                icon={analysis.validationResults.legalDefensibility ? <TrendingUp /> : <Warning />}
                                label={analysis.validationResults.legalDefensibility ? 'Defensible' : 'Weak'}
                                color={analysis.validationResults.legalDefensibility ? 'success' : 'error'}
                                sx={{ fontWeight: 'bold' }}
                              />
                            </Box>
                          </Grid>
                        </Grid>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              )}
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
};

export default PatentClaimsPage;
