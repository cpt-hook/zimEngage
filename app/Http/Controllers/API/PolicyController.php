<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Policy;
use Illuminate\Http\Request;

class PolicyController extends Controller
{
    public function index()
    {
        $policies = Policy::where('status', 'published')->get();
        return response()->json($policies);
    }

    public function store(Request $request)
    {
        $request->validate([
            'title' => 'required|string',
            'category' => 'required|string',
            'summary_en' => 'required|string',
            'objectives_en' => 'required|array',
            'implementation_en' => 'required|string',
            'impact_en' => 'required|string',
            'status' => 'required|in:draft,published,archived',
        ]);

        $policy = Policy::create([
            ...$request->all(),
            'created_by' => $request->user()->id,
        ]);

        return response()->json($policy, 201);
    }
}