// File upload by Elkeid
package transport

import (
	"context"
	"errors"
	"io"
	"os"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"github.com/chriskaliX/Hades/agent/proto"
	"github.com/chriskaliX/Hades/agent/transport/connection"
	_ "github.com/chriskaliX/Hades/agent/transport/compressor"
)

const (
	timeoutSeconds = 600
)

var (
	uploadCh = make(chan UploadRequest)
)

type UploadRequest struct {
	Path    string `json:"path"`
	BufSize int64  `json:"buf_size"`
	token   string
}

func UploadFile(req UploadRequest) (err error) {
	select {
	case uploadCh <- req:
	default:
		err = errors.New("last upload task hasn't completed")
	}
	return
}

func startFileExt(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer zap.S().Info("file_ext handler is exited")
	subWg := &sync.WaitGroup{}
	zap.S().Info("file_ext handler starts")
	defer subWg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-uploadCh:
			subWg.Add(1)
			handleUpload(ctx, subWg, req)
		}
	}
}

func handleUpload(ctx context.Context, wg *sync.WaitGroup, req UploadRequest) {
	defer wg.Done()
	zap.S().Infof("handle upload:%+v", req)
	var file *os.File
	file, err := os.Open(req.Path)
	if err != nil {
		TaskError(req.token, err.Error())
		return
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		TaskError(req.token, err.Error())
		return
	}
	if fileInfo.Size() > req.BufSize*timeoutSeconds {
		TaskError(req.token, fmt.Sprintf("size limit exceeded: (%v/%v)", fileInfo.Size(), req.BufSize*timeoutSeconds))
		return
	}
	conn, err := connection.GetConnection(ctx)
	if err != nil {
		TaskError(req.token, fmt.Errorf("no connection avaliable: %v", err).Error())
		return
	}
	var client proto.FileExt_UploadClient
	subCtx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(timeoutSeconds))
	defer cancel()
	client, err = proto.NewFileExtClient(conn).Upload(subCtx, grpc.UseCompressor("snappy"))
	if err != nil {
		TaskError(req.token, fmt.Errorf("no service available: %v", err).Error())
		return
	}
	var buf []byte
	if req.BufSize <= 500*1024 {
		buf = make([]byte, req.BufSize)
	} else {
		buf = make([]byte, 500*1024)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	expectedSize := fileInfo.Size()
	size := 0
	for {
		select {
		case <-ticker.C:
			n, rerr := io.ReadFull(file, buf)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				zap.S().Error(err)
				return
			}
			err = client.Send(
				&proto.FileUploadRequest{
					Token: req.token,
					Data:  buf[:n],
				},
			)
			if err != nil {
				zap.S().Error(err)
				return
			}
			size += n
			zap.S().Infof("upload process:%v/%v", size, expectedSize)
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				var resp *proto.FileUploadResponse
				resp, err = client.CloseAndRecv()
				if err != nil {
					zap.S().Error("upload failed:", err)
					return
				}
				zap.S().Info("upload completed:", resp.Status.String())
				return
			}
		case <-ctx.Done():
			return
		}
	}
}