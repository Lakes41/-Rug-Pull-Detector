import { NextResponse } from 'next/server';
import {
  buildAnalyzePayload,
  fetchTokenAnalysis,
  isValidAnalyzePayload,
  normalizeAnalysisResult,
} from '../../lib/report';

export async function POST(request) {
  try {
    const body = await request.json();
    const payload = buildAnalyzePayload(body);

    if (!isValidAnalyzePayload(payload)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing or invalid analysis inputs.',
        },
        { status: 400 }
      );
    }

    const result = await fetchTokenAnalysis(payload);

    if (!result.success) {
      return NextResponse.json(
        {
          success: false,
          error: result.error || 'Analysis failed.',
        },
        { status: 502 }
      );
    }

    let normalizedData = normalizeAnalysisResult(payload, result.data);

    // If this is a lending pool, get specialized risk analysis
    if (payload.isLendingPool) {
      try {
        const lendingPoolResponse = await fetch('http://localhost:8001/api/lending-pool-risk', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            poolAddress: payload.tokenAddress,
            poolType: payload.poolType || 'standard',
            baseRiskScore: normalizedData.riskScore || 0.3,
          }),
        });

        if (lendingPoolResponse.ok) {
          const lendingPoolData = await lendingPoolResponse.json();
          normalizedData = {
            ...normalizedData,
            lendingPoolAnalysis: {
              poolType: lendingPoolData.poolType,
              baseRiskScore: lendingPoolData.baseRiskScore,
              modifiedRiskScore: lendingPoolData.modifiedRiskScore,
              riskLevel: lendingPoolData.riskLevel,
              riskFactors: lendingPoolData.riskFactors,
              detectedAnomalies: lendingPoolData.detectedAnomalies,
              recommendations: lendingPoolData.recommendations,
            },
            riskScore: lendingPoolData.modifiedRiskScore,
            riskLevel: lendingPoolData.riskLevel,
          };
        }
      } catch (lendingError) {
        console.error('Lending pool analysis failed:', lendingError);
        // Continue with base analysis if lending pool analysis fails
      }
    }

    return NextResponse.json({
      success: true,
      data: normalizedData,
    });
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Unable to analyze token.',
      },
      { status: 500 }
    );
  }
}
