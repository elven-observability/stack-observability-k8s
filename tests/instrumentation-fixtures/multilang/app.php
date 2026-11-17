<?php
if(PHP_VERSION_ID<80512){http_response_code(503);exit;}
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if(!in_array($path,['/ready','/exercise'],true)){http_response_code(404);exit;}
$parts=explode('-',$_SERVER['HTTP_TRACEPARENT']??'');$tid=count($parts)===4?$parts[1]:'';
if($path==='/exercise'){file_put_contents('php://stdout',json_encode(['message'=>'Synthetic checkout approved','run'=>'elven-saas-20261116','trace_id'=>$tid,'email'=>'synthetic-customer@example.invalid','password'=>'synth-password-20261116']).PHP_EOL);}
header('Content-Type: application/json');echo json_encode(['ok'=>true,'runtime'=>PHP_VERSION,'traceId'=>$tid]);
