"use client";

import { useState } from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface AnalysisResult {
  risk: number;
  label: string;
  reasons: string[];
  meta: {
    keywords: Array<{ keyword: string; count: number }>;
    headers: Record<string, string>;
    key_headers: {
      from: string;
      to: string;
      cc: string;
      bcc: string;
      date: string;
      reply_to: string;
      return_path: string;
      message_id: string;
      content_type: string;
    };
    subject: string;
    body_preview: string;
    html_preview: string;
    domains: string[];
    whitelisted_domains: string[];
    content_stats: {
      body_length: number;
      html_length: number;
      has_html: boolean;
      domain_count: number;
    };
  };
}

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile && selectedFile.name.toLowerCase().endsWith(".eml")) {
      setFile(selectedFile);
      setError(null);
      setResult(null);
    } else {
      setFile(null);
      setError("Please select a valid .eml file");
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch("/api/py/analyze/eml", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Analysis failed");
      }

      const data: AnalysisResult = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk: number) => {
    if (risk >= 1.0) return "destructive";
    if (risk >= 0.5) return "secondary";
    return "default";
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-4">Phishing Email Analyzer</h1>
          <p className="text-lg text-muted-foreground">Upload an .eml file to analyze it for phishing indicators</p>
        </div>

        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Upload Email File</CardTitle>
            <CardDescription>Select an .eml file to analyze for potential phishing threats</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <Label htmlFor="file-upload">Email File (.eml)</Label>
                <Input id="file-upload" type="file" accept=".eml" onChange={handleFileChange} className="mt-1" />
                {file && <p className="text-sm text-muted-foreground mt-2">Selected: {file.name}</p>}
              </div>

              <Button onClick={handleAnalyze} disabled={!file || loading} className="w-full">
                {loading ? "Analyzing..." : "Analyze Email"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {error && (
          <Alert className="mb-8">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {result && (
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  Analysis Results
                  <Badge variant={getRiskColor(result.risk)}>{result.label}</Badge>
                </CardTitle>
                <CardDescription>Risk Score: {result.risk} / 1.0</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <h3 className="font-semibold mb-2">Risk Assessment</h3>
                    <div className="flex items-center gap-2">
                      <Badge variant={getRiskColor(result.risk)}>{result.label}</Badge>
                      <span className="text-sm text-muted-foreground">Score: {result.risk}</span>
                    </div>
                  </div>

                  {result.reasons.length > 0 && (
                    <div>
                      <h3 className="font-semibold mb-2">Reasons</h3>
                      <div className="flex flex-wrap gap-2">
                        {result.reasons.map((reason, index) => (
                          <Badge key={index} variant="outline">
                            {reason}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <h3 className="font-semibold mb-2">Subject</h3>
                    <p className="text-sm bg-muted p-2 rounded">{result.meta.subject || "No subject"}</p>
                  </div>

                  {result.meta.keywords.length > 0 && (
                    <div>
                      <h3 className="font-semibold mb-2">Detected Keywords</h3>
                      <div className="space-y-1">
                        {result.meta.keywords.map((kw, index) => (
                          <div key={index} className="flex justify-between text-sm">
                            <span>{kw.keyword}</span>
                            <Badge variant="secondary">{kw.count}</Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.meta.key_headers && (
                    <div>
                      <h3 className="font-semibold mb-2">Key Email Headers</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <span className="font-medium text-sm">From:</span>
                          <p className="text-sm bg-muted p-2 rounded mt-1">
                            {result.meta.key_headers.from || "Not specified"}
                          </p>
                        </div>
                        <div>
                          <span className="font-medium text-sm">To:</span>
                          <p className="text-sm bg-muted p-2 rounded mt-1">
                            {result.meta.key_headers.to || "Not specified"}
                          </p>
                        </div>
                        {result.meta.key_headers.cc && (
                          <div>
                            <span className="font-medium text-sm">CC:</span>
                            <p className="text-sm bg-muted p-2 rounded mt-1">{result.meta.key_headers.cc}</p>
                          </div>
                        )}
                        <div>
                          <span className="font-medium text-sm">Date:</span>
                          <p className="text-sm bg-muted p-2 rounded mt-1">
                            {result.meta.key_headers.date || "Not specified"}
                          </p>
                        </div>
                        {result.meta.key_headers.reply_to && (
                          <div>
                            <span className="font-medium text-sm">Reply-To:</span>
                            <p className="text-sm bg-muted p-2 rounded mt-1">{result.meta.key_headers.reply_to}</p>
                          </div>
                        )}
                        <div>
                          <span className="font-medium text-sm">Content-Type:</span>
                          <p className="text-sm bg-muted p-2 rounded mt-1">
                            {result.meta.key_headers.content_type || "Not specified"}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {result.meta.content_stats && (
                    <div>
                      <h3 className="font-semibold mb-2">Content Statistics</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="text-center">
                          <div className="text-2xl font-bold">{result.meta.content_stats.body_length || 0}</div>
                          <div className="text-sm text-muted-foreground">Body Length</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold">{result.meta.content_stats.html_length || 0}</div>
                          <div className="text-sm text-muted-foreground">HTML Length</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold">{result.meta.content_stats.domain_count || 0}</div>
                          <div className="text-sm text-muted-foreground">Domains Found</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold">{result.meta.content_stats.has_html ? "Yes" : "No"}</div>
                          <div className="text-sm text-muted-foreground">Has HTML</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {result.meta.body_preview && (
                    <div>
                      <h3 className="font-semibold mb-2">Body Content Preview</h3>
                      <div className="bg-muted p-3 rounded text-sm max-h-32 overflow-y-auto whitespace-pre-wrap">
                        {result.meta.body_preview}
                      </div>
                    </div>
                  )}

                  {result.meta.html_preview && (
                    <div>
                      <h3 className="font-semibold mb-2">HTML Content Preview</h3>
                      <div className="bg-muted p-3 rounded text-sm max-h-32 overflow-y-auto whitespace-pre-wrap">
                        {result.meta.html_preview}
                      </div>
                    </div>
                  )}

                  {result.meta.domains && result.meta.domains.length > 0 && (
                    <div>
                      <h3 className="font-semibold mb-2">Extracted Domains</h3>
                      <div className="space-y-2">
                        {result.meta.domains.map((domain, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <Badge
                              variant={
                                result.meta.whitelisted_domains && result.meta.whitelisted_domains.includes(domain)
                                  ? "default"
                                  : "secondary"
                              }
                            >
                              {domain}
                            </Badge>
                            {result.meta.whitelisted_domains && result.meta.whitelisted_domains.includes(domain) && (
                              <span className="text-xs text-green-600">Whitelisted</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <h3 className="font-semibold mb-2">All Email Headers</h3>
                    <div className="bg-muted p-3 rounded text-sm max-h-40 overflow-y-auto">
                      {Object.entries(result.meta.headers).map(([key, value]) => (
                        <div key={key} className="mb-1">
                          <span className="font-medium">{key}:</span> {value}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
