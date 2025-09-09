import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get("file") as File;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    // Forward the request to the Python backend
    const backendUrl = "http://127.0.0.1:8000";
    const backendResponse = await fetch(`${backendUrl}/api/py/analyze/eml`, {
      method: "POST",
      body: formData,
    });

    if (!backendResponse.ok) {
      const errorData = await backendResponse.json();
      return NextResponse.json(
        { detail: errorData.detail || "Backend analysis failed" },
        { status: backendResponse.status }
      );
    }

    const data = await backendResponse.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error("API route error:", error);
    return NextResponse.json({ detail: "Internal server error" }, { status: 500 });
  }
}
