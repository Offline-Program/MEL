// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tract_onnx::prelude::*;
use tract_onnx::tract_core::dims;
use tokenizers::Tokenizer;

/// File name of the ONNX embedding model within the model directory.
const MODEL_FILE: &str = "model.onnx";
/// File name of the tokenizer configuration within the model directory.
const TOKENIZER_FILE: &str = "tokenizer.json";

type Model = RunnableModel<TypedFact, Box<dyn TypedOp>>;

/// Generates vector embeddings from text using an ONNX model.
///
/// Uses CLS pooling with L2 normalization, matching the behavior of
/// `ibm-granite/granite-embedding-30m-english` and its successors.
pub struct Embedder {
    model: Arc<Model>,
    tokenizer: Tokenizer,
}

impl Embedder {
    /// Loads the ONNX model and tokenizer from `model_dir`.
    ///
    /// Expects `model.onnx` and `tokenizer.json` to exist inside `model_dir`.
    ///
    /// Returns `Err` if either file cannot be read, the ONNX model bytes are
    /// invalid, shape inference or optimization fails, or the tokenizer JSON
    /// cannot be parsed.
    pub fn new(model_dir: impl AsRef<Path>) -> Result<Self> {
        let model_dir = model_dir.as_ref();
        let model_path = model_dir.join(MODEL_FILE);
        let tokenizer_path = model_dir.join(TOKENIZER_FILE);

        let mut model_file = File::open(&model_path)
            .with_context(|| format!("failed to open ONNX model at {}", model_path.display()))?;
        let inference_model = tract_onnx::onnx().model_for_read(&mut model_file)?;
        let s = inference_model.sym("S");

        let model = inference_model
            .with_input_fact(0, i64::fact(dims!(1, s)).into())?
            .with_input_fact(1, i64::fact(dims!(1, s)).into())?
            .into_optimized()?
            .into_runnable()?;

        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|e| {
            anyhow::anyhow!("failed to load tokenizer at {}: {e}", tokenizer_path.display())
        })?;

        Ok(Self { model, tokenizer })
    }

    /// Generates a 384-dimensional embedding vector for the given text.
    ///
    /// The text is tokenized (truncated to the model's max context length),
    /// passed through the ONNX model, and the CLS token embedding is extracted
    /// and L2-normalized.
    ///
    /// Returns `Err` if tokenization fails or model inference errors.
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| m as i64)
            .collect();
        let seq_len = input_ids.len();

        let input_ids_tensor = Tensor::from_shape(&[1, seq_len], &input_ids)?;
        let attn_mask_tensor = Tensor::from_shape(&[1, seq_len], &attention_mask)?;

        let outputs = self.model.run(tvec!(
            input_ids_tensor.into_tvalue(),
            attn_mask_tensor.into_tvalue(),
        ))?;

        let output = &outputs[0];
        let view = output.try_as_plain()?;
        let embeddings = view.as_slice::<f32>()?;

        let shape = output.shape();
        let hidden_dim = *shape
            .last()
            .ok_or_else(|| anyhow::anyhow!("empty output shape from model"))?;
        let cls_vec: Vec<f32> = embeddings[..hidden_dim].to_vec();

        Ok(l2_normalize(cls_vec))
    }
}

/// L2-normalizes a vector in place, returning the normalized result.
/// Returns a zero vector unchanged.
fn l2_normalize(mut vec: Vec<f32>) -> Vec<f32> {
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for val in &mut vec {
            *val /= norm;
        }
    }
    vec
}
