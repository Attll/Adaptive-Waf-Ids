import unittest
from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.features.inspection import inspection_text,inspection_group


class InspectionRepresentationTests(unittest.TestCase):
    def test_gateway_filtered_metadata_does_not_change_candidate_view(self):
        full=HttpRequestRecord('GET','/search','q=normal',headers={'Host':'fixture','User-Agent':'scanner','Date':'yesterday','Set-Cookie':'response','Content-Type':'text/plain'})
        wire=HttpRequestRecord('GET','/search','q=normal',headers={'content-type':'text/plain'})
        self.assertEqual(inspection_text(full),inspection_text(wire))
        self.assertEqual(inspection_group(full),inspection_group(wire))

    def test_payload_fields_receive_bounded_windows_even_after_long_fields(self):
        request=HttpRequestRecord('POST','/a'+('x'*10000),'q='+('y'*10000)+'query-tail',cookies={'s':'z'*10000+'cookie-tail'},body='w'*10000+'body-tail')
        result=inspection_text(request,1024)
        self.assertLessEqual(len(result.text),1024)
        for value in ('query-tail','cookie-tail','body-tail'):self.assertIn(value,result.text)
        self.assertIn('BODY',result.truncated_fields)

    def test_equivalent_query_encoding_shares_group_without_erasing_raw_input(self):
        a=HttpRequestRecord('GET','/search','q=%3Ctag%3E')
        b=HttpRequestRecord('GET','/search','q=<tag>')
        self.assertEqual(inspection_group(a),inspection_group(b))
        self.assertIn('%3Ctag%3E',inspection_text(a).text)
        self.assertIn('<tag>',inspection_text(a).text)

    def test_path_plus_is_not_form_space(self):
        self.assertNotEqual(inspection_group(HttpRequestRecord('GET','/a+b')),inspection_group(HttpRequestRecord('GET','/a%20b')))
