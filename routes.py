from flask import render_template, request, jsonify, flash
from app import app
from core.scanner import scan_target
from core.cache import ScanCache
import asyncio
import logging

cache = ScanCache()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target = data.get('target')
        port_range = data.get('port_range', '1-1024')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Check cache first
        cached_results = cache.get_results(target)
        if cached_results:
            return jsonify({'results': cached_results, 'cached': True})

        # Run new scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(scan_target(target, port_range))
        loop.close()
        
        # Cache the results
        cache.store_results(target, results)
        
        # Log the AI analysis results for debugging
        logging.debug(f"AI Analysis results: {results.get('ai_analysis', {})}")
        
        response_data = {
            'results': results.get('scan_results', []),
            'ai_analysis': results.get('ai_analysis', {}),
            'cached': False
        }
        logging.info("Scan completed successfully with AI analysis")
        return jsonify(response_data)

    except ValueError as e:
        logging.error(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logging.error(f"Scan error: {str(e)}")
        return jsonify({'error': 'An error occurred during the scan'}), 500

@app.route('/results/<target>')
def view_results(target):
    results = cache.get_results(target)
    if not results:
        flash('No results found for this target', 'warning')
        return render_template('results.html', target=target, results=[])
    
    return render_template('results.html', target=target, results=results)
