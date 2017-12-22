"""
Views related to the transcript preferences feature
"""
import os
import json
import logging

from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import HttpResponseNotFound, HttpResponse
from django.utils.translation import ugettext as _
from django.views.decorators.http import require_POST, require_GET
from edxval.api import (
    create_or_update_video_transcript,
    get_3rd_party_transcription_plans,
    get_video_transcript_data,
    update_transcript_credentials_state_for_org,
)
from opaque_keys.edx.keys import CourseKey

from openedx.core.djangoapps.video_config.models import VideoTranscriptEnabledFlag
from openedx.core.djangoapps.video_pipeline.api import update_3rd_party_transcription_service_credentials
from util.json_request import JsonResponse, expect_json

from contentstore.views.videos import TranscriptProvider
from xmodule.video_module.transcripts_utils import Transcript, generate_subs_from_source

__all__ = ['transcript_credentials_handler', 'transcript_download_handler', 'transcript_upload_handler']

LOGGER = logging.getLogger(__name__)


class TranscriptionProviderErrorType:
    """
    Transcription provider's error types enumeration.
    """
    INVALID_CREDENTIALS = 1


def validate_transcript_credentials(provider, **credentials):
    """
    Validates transcript credentials.

    Validations:
        Providers must be either 3PlayMedia or Cielo24.
        In case of:
            3PlayMedia - 'api_key' and 'api_secret_key' are required.
            Cielo24 - 'api_key' and 'username' are required.

        It ignores any extra/unrelated parameters passed in credentials and
        only returns the validated ones.
    """
    error_message, validated_credentials = '', {}
    valid_providers = get_3rd_party_transcription_plans().keys()
    if provider in valid_providers:
        must_have_props = []
        if provider == TranscriptProvider.THREE_PLAY_MEDIA:
            must_have_props = ['api_key', 'api_secret_key']
        elif provider == TranscriptProvider.CIELO24:
            must_have_props = ['api_key', 'username']

        missing = [must_have_prop for must_have_prop in must_have_props if must_have_prop not in credentials.keys()]
        if missing:
            error_message = u'{missing} must be specified.'.format(missing=' and '.join(missing))
            return error_message, validated_credentials

        validated_credentials.update({
            prop: credentials[prop] for prop in must_have_props
        })
    else:
        error_message = u'Invalid Provider {provider}.'.format(provider=provider)

    return error_message, validated_credentials


@expect_json
@login_required
@require_POST
def transcript_credentials_handler(request, course_key_string):
    """
    JSON view handler to update the transcript organization credentials.

    Arguments:
        request: WSGI request object
        course_key_string: A course identifier to extract the org.

    Returns:
        - A 200 response if credentials are valid and successfully updated in edx-video-pipeline.
        - A 404 response if transcript feature is not enabled for this course.
        - A 400 if credentials do not pass validations, hence not updated in edx-video-pipeline.
    """
    course_key = CourseKey.from_string(course_key_string)
    if not VideoTranscriptEnabledFlag.feature_enabled(course_key):
        return HttpResponseNotFound()

    provider = request.json.pop('provider')
    error_message, validated_credentials = validate_transcript_credentials(provider=provider, **request.json)
    if error_message:
        response = JsonResponse({'error': error_message}, status=400)
    else:
        # Send the validated credentials to edx-video-pipeline.
        credentials_payload = dict(validated_credentials, org=course_key.org, provider=provider)
        error_response, is_updated = update_3rd_party_transcription_service_credentials(**credentials_payload)
        # Send appropriate response based on whether credentials were updated or not.
        if is_updated:
            # Cache credentials state in edx-val.
            update_transcript_credentials_state_for_org(org=course_key.org, provider=provider, exists=is_updated)
            response = JsonResponse(status=200)
        else:
            # Error response would contain error types and the following
            # error type is received from edx-video-pipeline whenever we've
            # got invalid credentials for a provider. Its kept this way because
            # edx-video-pipeline doesn't support i18n translations yet.
            error_type = error_response.get('error_type')
            if error_type == TranscriptionProviderErrorType.INVALID_CREDENTIALS:
                error_message = _('The information you entered is incorrect.')

            response = JsonResponse({'error': error_message}, status=400)

    return response


@expect_json
@login_required
@require_GET
def transcript_download_handler(request, course_key_string):
    """
    JSON view handler to download a transcript.

    Arguments:
        request: WSGI request object
        course_key_string: course key
        filename: Name of the to be created transcript file

    Returns:
        - A 200 response with SRT transcript file attached.
        - A 400 if there is a validation error.
        - A 404 if there is no such transcript or feature flag is disabled.
    """
    course_key = CourseKey.from_string(course_key_string)
    if not VideoTranscriptEnabledFlag.feature_enabled(course_key):
        return HttpResponseNotFound()

    edx_video_id = request.GET.get('edx_video_id')
    if not edx_video_id:
        return JsonResponse({'error': 'edx_video_id is required.'}, status=400)

    language_code = request.GET.get('language_code')
    if not language_code:
        return JsonResponse({'error': 'language code is required.'}, status=400)

    transcript = get_video_transcript_data(video_ids=[edx_video_id], language_code=language_code)
    if transcript:
        basename, __ = os.path.splitext(transcript['file_name'])
        transcript_filename = '{base_name}.srt'.format(base_name=basename.encode('utf8'))
        transcript_content = Transcript.convert(transcript['content'], input_format='sjson', output_format='srt')
        # Construct an HTTP response
        response = HttpResponse(transcript_content, content_type=Transcript.mime_types['srt'])
        response['Content-Disposition'] = 'attachment; filename="{filename}"'.format(filename=transcript_filename)
    else:
        response = HttpResponseNotFound()

    return response


def validate_video_transcript(transcript_file):
    """
    Validates video transcript file.

    Arguments:
        transcript_file: The selected transcript file.

   Returns:
        None or String
        If there is error returns error message otherwise None.
    """
    error = None
    if not all(hasattr(transcript_file, attr) for attr in ['name', 'content_type']):
        error = _(u'The transcript must have name and content type information.')
    elif transcript_file.content_type != 'srt':
        error = _(u'This transcript file type is not supported. Supported file type is SRT only.')

    return error


@expect_json
@login_required
@require_POST
def transcript_upload_handler(request, course_key_string):
    """
    JSON view handler to upload a transcript file.

    Arguments:
        request: A WSGI request object
        course_key_string: Course key identifying a course

    Transcript file, edx video id and transcript language are required.
    Transcript file should be in SRT(SubRip) format.

    Returns
        - A 400 if any of the validation fails
        - A 404 if the corresponding feature flag is disabled
        - A 200 if transcript has been uploaded successfully
    """
    # Check whether the feature is available for this course.
    course_key = CourseKey.from_string(course_key_string)
    if not VideoTranscriptEnabledFlag.feature_enabled(course_key):
        return HttpResponseNotFound()

    # Validate the must have attributes - this error is unlikely to be faced by common users.
    must_have_attrs = ['edx_video_id', 'language_code']
    missing = [attr for attr in must_have_attrs if attr not in request.json]
    if missing:
        return JsonResponse({
            'error': _(u'Following parameters are required {missing}.').format(missing=','.join(missing))
        }, status=400)

    if 'file' not in request.FILES:
        return JsonResponse({'error': _(u'A transcript file is required.')}, status=400)

    # Validate the transcript file.
    edx_video_id = request.json['edx_video_id']
    language_code = request.json['language_code']
    transcript_file = request.FILES['file']
    error = validate_video_transcript(transcript_file)
    if error:
        return JsonResponse({'error': error}, status=400)

    # Convert SRT transcript into an SJSON format and upload it to S3
    try:
        sjson_subs = Transcript.convert(content=transcript_file.read(), input_format='srt', output_format='sjson')
        transcript_url = create_or_update_video_transcript(
            video_id=edx_video_id,
            language_code=language_code,
            file_name='subs.sjson',
            file_format='sjson',
            provider='Custom',
            file_data=ContentFile(json.dumps(sjson_subs)),
        )
    except Exception:
        LOGGER.exception(
            u'Transcript upload failed for course=%s, edx_video_id=%s, language_code=%s.',
            course_key_string, edx_video_id, language_code
        )
        raise

    return JsonResponse({'transcript_url': transcript_url})
